#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/poll.h>
#include <stdatomic.h>
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <fcntl.h>

#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include <enet.h>
#include <internal/errors.h>
#include <internal/smem.h>

#if defined(_EN_CUSTOM_CRC)
#	include <internal/crc.h>
#	define crc32 _en_crc32
#else
#	include <zlib.h>
#endif

#ifndef __VERSION
#define __VERSION 0 /* No version defined by Make? */
#endif

#define ISFLAG(haystack, needle) ((needle & haystack) == needle)

#define HTON(sock, val, s) (_en_flagset(sock, EN_SOCKFLAG_NO_HTON)?val:hton##s(val))
#define NTOH(sock, val, s) (_en_flagset(sock, EN_SOCKFLAG_NO_HTON)?val:ntoh##s(val))

#define EN_ERRBUFF_SIZE 256
#define EN_TMPBUFF_SIZE 512

///TODO: Mutexes & thread safety (maybe?)
///TODO: Make work on Windows/MinGW

struct esock_t {
	int con;
	
	RSA *local, *remote;
	
	struct en_aes_key aes_read_key, aes_write_key;
	EVP_CIPHER_CTX *aes_read, *aes_write;
	
	_en_ecode_t errorcode;
	
	ssize_t log_read;
	ssize_t log_written;
	
	long fb_timeout;
	
	jmp_buf* errjmp;
	
	unsigned int flags;
	
	sm_context smc_read;
	sm_context smc_read_ct;
	
	char errbuff[EN_ERRBUFF_SIZE];
	char tmpbuff[EN_TMPBUFF_SIZE];
};

#define _EN_FAIL(sock, ec) { sock->errorcode = ec; return EN_FAILURE; }

static int _en_sockblock(int fd, int blocking)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) return 0;
	flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
	return (fcntl(fd, F_SETFL, flags) == 0) ? 1 : 0;
}

static long _en_timems()
{
	struct timespec sp;
	clock_gettime(CLOCK_REALTIME, &sp);
	
	return (sp.tv_sec*1000)+((long)(sp.tv_nsec/1.e6));
}

EVP_CIPHER_CTX* en_readAES(esock_t sock)
{
	return sock->aes_read;
}

EVP_CIPHER_CTX* en_writeAES(esock_t sock)
{
	return sock->aes_write;
}

static void _en_fail_jmp(esock_t sock)
{
	if(sock->errjmp!=NULL) {
		jmp_buf *buf;
		buf = sock->errjmp;
		sock->errjmp=NULL;
		longjmp(*buf, sock->errorcode);
	}
}

static int _en_fail(esock_t sock, int ec)
{
	sock->errorcode = ec;
	_en_fail_jmp(sock);
	return EN_FAILURE;
}

static int _en_fail_nj(esock_t sock, int ec)
{
	sock->errorcode = ec;
	return EN_FAILURE;
}

void en_seterrjmp(esock_t sock, jmp_buf *buffer)
{
	sock->errjmp = buffer;
}

static RSA* _en_create_keypair()
{
	return RSA_generate_key(EN_RSA_KEYSIZE, EN_RSA_EXP, NULL, NULL);
}

static int _en_flagset(esock_t s, unsigned int f)
{
	return ISFLAG(s->flags, f);
}

esock_t en_create_socket(int con, RSA *rsa)
{
	esock_t es = (esock_t)malloc(sizeof(struct esock_t));
	memset(es, 0, sizeof(struct esock_t));
	
	es->con = con;
	es->local = (rsa==NULL?_en_create_keypair():rsa);
	es->remote = NULL;
	es->smc_read = _en_sm_init();
	es->smc_read_ct = _en_sm_init();
	
	es->aes_read = es->aes_write = NULL;
	
	return es;
}

static struct en_rsa_pub _en_get_pub(RSA *rsa)
{
	struct en_rsa_pub pub;
	const BIGNUM* n, *e;
	
	memset(&pub,0,sizeof(struct en_rsa_pub));
	
	RSA_get0_key(rsa, &n, &e, NULL);
	
	assert( (BN_num_bytes(e)<=EN_RSAP_EXPSIZE) && (BN_num_bytes(n) == EN_RSAP_MODSIZE) );
	
	BN_bn2bin(n, pub.mod);
	
	BN_bn2bin(e, pub.exp);
	
	return pub;
}

RSA* en_localRSA(esock_t sock)
{
	return sock->local;
}

RSA* en_remoteRSA(esock_t sock)
{
	return sock->remote;
}

void en_publickeys(esock_t sock, struct en_rsa_pub *local, struct en_rsa_pub *remote)
{
	if(local!=NULL) 
		*local = _en_get_pub(sock->local);
	if(remote!=NULL)
		*remote = _en_get_pub(sock->remote);
}

static char* _en_hexstr(char* buf, int bs, const unsigned char* bytes, int num)
{
	register int i=0;
	char* nb = buf;
	for(;(i*2)<bs&&i<num;i++)
	{
		sprintf(nb, "%02x", bytes[i]);
		nb+=2;
	}
	return buf;
}

char* en_rsa_pub_f(char* buffer, int bs, const struct en_rsa_pub *key)
{
	char mods[ (EN_RSAP_MODSIZE*2)+1];
	char exps[ (EN_RSAP_EXPSIZE*2)+1];
	memset(mods, 0, (EN_RSAP_MODSIZE*2)+1);
	memset(exps, 0, (EN_RSAP_EXPSIZE*2)+1);
	_en_hexstr(mods, (EN_RSAP_MODSIZE*2), key->mod, EN_RSAP_MODSIZE);
	_en_hexstr(exps, (EN_RSAP_EXPSIZE*2), key->exp, EN_RSAP_EXPSIZE);
	snprintf(buffer,bs,"[mod: %s, exp: %s (crc32: %lx)]", mods, exps, crc32(EN_CRC32_SEED, (const unsigned char*)key, sizeof(struct en_rsa_pub)));
	return buffer;
}

static ssize_t __en_read(int con, unsigned char* buf, int len)
{
	ssize_t ret = read(con, buf,len);
	if(ret<0) return 0;
	return ret;
}

static ssize_t _en_forceread(esock_t con, unsigned char* buf, int len, jmp_buf oto)
{
	ssize_t vr=0;
	long tm_begin= _en_timems();
	//printf("_en_forceread: begining loop with time %ld (timeout %ld)\r\n", tm_begin, con->fb_timeout);
	while( (vr+=__en_read(con->con, buf+vr, len-vr)) != len) {
		if(con->fb_timeout>0) {
			long tm_now = _en_timems();
			//printf("_en_forceread: new time is %ld (countdown: %ld)\r\n", tm_now, (tm_now-tm_begin));
			if( (tm_now-tm_begin)>=con->fb_timeout) { longjmp(oto, 1); }
		}
	}
	return vr;
}

static ssize_t _en_read(esock_t con, void* buf, int len, jmp_buf lje)
{
	if(_en_flagset(con, EN_SOCKFLAG_FORCEBLOCK)) return _en_forceread(con,(unsigned char*)buf,len, lje);
	else 
	{
		//printf("_en_read: using normal read\r\n");
		return read(con->con, buf, len);
	}
}

int en_exchange(esock_t sock)
{
	struct en_rsa_pub pub = _en_get_pub(sock->local);
	struct en_rsa_pub rpub;
	uint32_t local_crc,remote_crc;
	jmp_buf to0;
	
	if( setjmp(to0)!=0)
	{
		return _en_fail(sock, ENE_READ_TIMEOUT);
	}
	
	int bypassCS = _en_flagset(sock,EN_SOCKFLAG_NOCHECKSUM);
	
	local_crc= HTON(sock, crc32(EN_CRC32_SEED, (unsigned char*)&pub, sizeof(struct en_rsa_pub)), l);
	
	if( write(sock->con, &pub, sizeof(struct en_rsa_pub)) != sizeof(struct en_rsa_pub)) return _en_fail(sock, ENE_RSAE_WRITE_FAIL);
	if( write(sock->con, &local_crc, sizeof(uint32_t)) != sizeof(uint32_t)) return _en_fail(sock, ENE_RSAE_WRITE_FAIL);
	if( _en_read(sock, &rpub, sizeof(struct en_rsa_pub), to0) == sizeof(struct en_rsa_pub))
	{
		if( (_en_read(sock, &remote_crc, sizeof(uint32_t), to0) == sizeof(uint32_t)))
		{
			remote_crc = NTOH(sock, remote_crc, l);
			if( bypassCS || ( crc32(EN_CRC32_SEED, (unsigned char*)&rpub, sizeof(struct en_rsa_pub))==remote_crc) )
			{
				BIGNUM* n, *e;
				if(sock->remote!=NULL)
					RSA_free(sock->remote);
				
				n = BN_bin2bn(rpub.mod, EN_RSAP_MODSIZE, NULL);
				e = BN_bin2bn(rpub.exp, EN_RSAP_EXPSIZE, NULL);
				
				sock->remote = _en_create_keypair();
				RSA_set0_key(sock->remote, n, e, NULL);
				
				/*BN_free(n);
				BN_free(e);*/ //Do I need to do this?
				return EN_SUCCESS;
			}
			return _en_fail(sock, ENE_RSAE_INVALID_CHECKSUM);
		}
		else return _en_fail(sock, ENE_RSAE_INCORRECT_SIZE);
	}
	else return _en_fail(sock, ENE_RSAE_INCORRECT_SIZE);
}

static EVP_CIPHER_CTX* _en_aes_create(unsigned char* key, unsigned char* iv, int en)
{
	EVP_CIPHER_CTX* ctx;
	if(!(ctx = EVP_CIPHER_CTX_new())) return NULL; 
	if(en) {
		if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) { EVP_CIPHER_CTX_free(ctx); return NULL; }
	}
	else {
		if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) { EVP_CIPHER_CTX_free(ctx); return NULL; }
	}
	return ctx;	
}





static int _en_set_uenc_write(esock_t s)
{
	if(s->aes_write==NULL) return _en_fail(s, ENE_USWRITE_NOT_AQUIRED);
	EVP_CIPHER_CTX_free(s->aes_write);
	s->aes_write = NULL;
	return EN_SUCCESS;
}

static int _en_set_uenc_read(esock_t s)
{
	if(s->aes_read==NULL) return _en_fail(s, ENE_USREAD_NOT_AQUIRED);
	EVP_CIPHER_CTX_free(s->aes_read);
	s->aes_read = NULL;
	return EN_SUCCESS;
}

static int _en_set_enc_write(esock_t s)
{
	if(s->aes_write !=NULL) return _en_fail(s, ENE_SWRITE_ALREADY_AQUIRED);
	if(!RAND_bytes((unsigned char*)&s->aes_write_key, sizeof(struct en_aes_key))) return _en_fail(s, ENE_SWRITE_KEYGEN_FAILURE);
	else {
		unsigned char* ct = (unsigned char*)malloc(RSA_size(s->remote));
		int32_t len;
		if( (len=RSA_public_encrypt(sizeof(struct en_aes_key), (unsigned char*)&s->aes_write_key, ct, s->remote, RSA_PKCS1_PADDING)) > 0)
		{
			uint32_t crc = HTON(s, crc32(EN_CRC32_SEED, (unsigned char*)ct, len),l);
			len = (int32_t)HTON(s, (uint32_t)len, l);
			
			write(s->con, &len, sizeof(int32_t));
			write(s->con, ct, (int32_t)NTOH(s, (uint32_t)len, l));
			write(s->con, &crc, sizeof(uint32_t));
		}
		else { free(ct); return _en_fail(s, ENE_SWRITE_SSL_FAILURE); }
		free(ct);
		if( (s->aes_write = _en_aes_create(s->aes_write_key.key, s->aes_write_key.iv, 1)) == NULL) return _en_fail(s, ENE_SWRITE_AES_FAILURE);
		return EN_SUCCESS;
	}
}

static int _en_set_enc_read(esock_t s)
{
	if(s->aes_read != NULL) return _en_fail(s, ENE_SREAD_ALREADY_AQUIRED);
	else {
		int32_t len;
		uint32_t crc;
		unsigned char* ct;
		int bypassCS = _en_flagset(s, EN_SOCKFLAG_NOCHECKSUM);
		jmp_buf to0,to1;
		
		if(setjmp(to0)!=0)
		{
			return _en_fail(s, ENE_READ_TIMEOUT);
		}
		
		if( _en_read(s, &len, sizeof(int32_t), to0) != sizeof(int32_t)) return _en_fail(s, ENE_SREAD_INCORRECT_SIZE);
		len = (int32_t)NTOH(s, (uint32_t)len,l);
		
		ct = (unsigned char*)malloc(len);
		
		if(setjmp(to1)!=0)
		{
			free(ct);
			return _en_fail(s, ENE_READ_TIMEOUT);
		}
		
		if( _en_read(s, ct, len, to1) != len) {free(ct); return _en_fail(s, ENE_SREAD_INCORRECT_SIZE);}
		if( _en_read(s, &crc, sizeof(uint32_t), to1) != sizeof(uint32_t)) {free(ct); return _en_fail(s, ENE_SREAD_INCORRECT_SIZE);}
		crc = NTOH(s, crc, l);
		if( bypassCS || (crc32(EN_CRC32_SEED, ct, len) == crc))
		{
			unsigned char* dec = (unsigned char*)malloc(RSA_size(s->local));
			
			if(RSA_private_decrypt(len, ct, dec, s->local, RSA_PKCS1_PADDING)>0)
			{
				memcpy(&s->aes_read_key, dec, sizeof(struct en_aes_key));
				free(dec);
				free(ct);
				
				return ((s->aes_read = _en_aes_create(s->aes_read_key.key, s->aes_read_key.iv, 0))==NULL?_en_fail(s, ENE_SREAD_AES_FAILURE):EN_SUCCESS);
			}
			else {
				free(dec); free(ct); return _en_fail(s, ENE_SREAD_SSL_FAILURE);
			}
		}
		else {
			free(ct); return _en_fail(s, ENE_SREAD_INVALID_CHECKSUM);
		}
		
	}
}

int en_set(esock_t sock, int flag, int on)
{
	if( ISFLAG(flag, EN_READ) )
	{
		if(on)
		{
			return _en_set_enc_read(sock);
		}
		else return _en_set_uenc_read(sock);
	}
	if( ISFLAG(flag, EN_WRITE) ) {
		if(on)
		{
			return _en_set_enc_write(sock);
		}
		else return _en_set_uenc_write(sock);
	}
	return _en_fail(sock, ENE_SET_UNKNOWN_FLAG);
}

static int _en_roundUp(int numToRound, int multiple)
{
	int remainder;
	if (multiple == 0)
		return numToRound;
	
	remainder = abs(numToRound) % multiple;
	if (remainder == 0)
		return numToRound;
	if (numToRound < 0)
		return -(abs(numToRound) - remainder);
	return numToRound + multiple - remainder;
}

int en_get(esock_t sock, int flag)
{
	int iew = sock->aes_write!=NULL;
	int ier = sock->aes_read!=NULL;
	
	int ok;
	if( ISFLAG(flag, EN_READ) && ISFLAG(flag, EN_WRITE) ) ok = ier && iew;
	else {
		if( ISFLAG(flag, EN_READ) ) ok = ier;
		if( ISFLAG(flag, EN_WRITE) ) ok = iew;
	}
	return ok;
}

ssize_t en_write(esock_t sock, void* _buf, size_t count)
{
	unsigned char* buf = (unsigned char*)_buf;
	if(en_get(sock, EN_WRITE))
	{
		int rctl = count%16==0?count+16:_en_roundUp(count, 16);
		unsigned char* ct = (unsigned char*)malloc(rctl);
		int len, ctl;
		int rv= -1;
		ssize_t ret=-1;
		memset(ct,0,rctl);
		if(EVP_EncryptUpdate(sock->aes_write, ct, &len, buf, count))
		{
			ctl=len;
			if(EVP_EncryptFinal_ex(sock->aes_write, ct+len, &len))
			{
				ctl+=len;
				if( (ret = write(sock->con, ct, rctl))!=rctl)
				{
					rv = _en_fail_nj(sock, ENE_WRITE_FAIL);
				}
				if(_en_flagset(sock, EN_SOCKFLAG_LOG)) sock->log_written+=count;
				EVP_CIPHER_CTX_free(sock->aes_write);
				if( (sock->aes_write = _en_aes_create(sock->aes_write_key.key, sock->aes_write_key.iv,1)) == NULL) rv = _en_fail_nj(sock, ENE_WRITE_AES_RELOAD_FAIL);
				else if(rv!=EN_FAILURE)
					rv = EN_SUCCESS;
				
			} else rv = _en_fail_nj(sock, ENE_WRITE_AES_FINAL_FAIL);
		} else rv = _en_fail_nj(sock, ENE_WRITE_AES_UPDATE_FAIL);
		free(ct);
		if(rv== EN_SUCCESS) return ret; else { _en_fail_jmp(sock); return -1; }
	}
	else {
		
		ssize_t w = write(sock->con, buf,count);
		if(_en_flagset(sock, EN_SOCKFLAG_LOG)) sock->log_written+=w;
		return w;
	}
}


ssize_t en_read(esock_t sock, void* _buf, size_t count)
{
	
	if(en_get(sock, EN_READ))
	{
		int rctl = count%16==0?count+16:_en_roundUp(count, 16);
		unsigned char* ct = (unsigned char*)_en_smalloc(sock->smc_read_ct, rctl);
		ssize_t ret=-1;
		jmp_buf env_timeout;
		
		
		unsigned char* buf = (unsigned char*)_en_smalloc(sock->smc_read, count+16+1);
		
		memset(buf,0,count+16);
		buf[count+16]=0xaf; //this check is probably not needed anymore
		
		if (setjmp(env_timeout)!=0)
		{
			//timeout reached
			_en_fail_nj(sock, ENE_READ_TIMEOUT);
		}
		else if( _en_read(sock, ct,rctl, env_timeout) == rctl )
		{
			int len, ptl;
			if(EVP_DecryptUpdate(sock->aes_read, buf, &len, ct, rctl)==1)
			{
				ptl = len;
				if(EVP_DecryptFinal_ex(sock->aes_read, buf+len, &len)==1)
				{
					if(buf[count+16]!=0xaf) {
						_en_fail(sock, ENE_FATAL_HEAP_CORRUPTION);
						return -1;
					}
					else {
						ptl+=len;
						if(_en_flagset(sock, EN_SOCKFLAG_LOG)) sock->log_read+=count;
						
						memcpy(_buf, buf, count);
						ret = ptl;
						
					}
				}
				else _en_fail_nj(sock, ENE_READ_AES_FINAL_FAIL);
			}
			else _en_fail_nj(sock, ENE_READ_AES_UPDATE_FAIL);
			
			EVP_CIPHER_CTX_free(sock->aes_read);
			if( (sock->aes_read = _en_aes_create(sock->aes_read_key.key, sock->aes_read_key.iv,0)) == NULL) {
				 _en_fail_nj(sock, ENE_READ_AES_RELOAD_FAIL);
				ret=-1;
			}
			
		}
		else {
			_en_fail_nj(sock, ENE_READ_INCORRECT_SIZE);
		}
		_en_sm_clear(sock->smc_read);
		_en_sm_clear(sock->smc_read_ct);
		//free(ct); <-- V
		//free(buf); <- sm_free is handled later
		if(ret<=0) _en_fail_jmp(sock);
		return ret;
	}
	else {
		jmp_buf tob;
		unsigned char* buf = (unsigned char*)_buf;
		
		if( setjmp(tob)!=0)
		{
			//timeout
			_en_fail(sock, ENE_READ_TIMEOUT);
			return -1;
		}
		else {
			ssize_t r = _en_read(sock, buf, count, tob);
			if(_en_flagset(sock, EN_SOCKFLAG_LOG)) sock->log_read+=r;
			return r;
		}
	}
}

void en_get_aes_read_key(esock_t sock, struct en_aes_key* key)
{
	memcpy(key, &sock->aes_read_key, sizeof(struct en_aes_key));	
}

void en_get_aes_write_key(esock_t sock, struct en_aes_key* key)
{
	memcpy(key, &sock->aes_write_key, sizeof(struct en_aes_key));	
}

char* en_aes_f(char* buffer, int bs, const struct en_aes_key *akey)
{
	char key[ (EN_AESP_KEYSIZE*2)+1];
	char iv[ (EN_AESP_IVSIZE*2)+1];
	memset(key, 0, (EN_AESP_KEYSIZE*2)+1);
	memset(iv, 0, (EN_AESP_IVSIZE*2)+1);
	_en_hexstr(key, (EN_AESP_KEYSIZE*2), akey->key, EN_AESP_KEYSIZE);
	_en_hexstr(iv, (EN_AESP_IVSIZE*2), akey->iv, EN_AESP_IVSIZE);
	snprintf(buffer,bs,"[key: %s, iv: %s (crc32: %lx)]", key, iv, crc32(EN_CRC32_SEED, (const unsigned char*)akey ,sizeof(struct en_aes_key)));
	return buffer;
}

void en_close(esock_t s, int flags)
{
	s->errjmp=NULL;
	
	_en_set_uenc_write(s);
	_en_set_uenc_read(s);
	
	if(!ISFLAG(flags, EN_CLOSE_KEEPALIVE)) close(s->con);
	if(!ISFLAG(flags, EN_CLOSE_KEEPRSA)) {
		if(s->local!=NULL) RSA_free(s->local);
		if(s->remote!=NULL) RSA_free(s->remote);
	}
	
	_en_sm_free(s->smc_read);
	_en_sm_free(s->smc_read_ct);
	
	memset(s, 0, sizeof(struct esock_t));
	free(s);
}

const char* en_error(esock_t sock)
{
	char buf[512];
	//memset(sock->tmpbuff,0,EN_TMPBUFF_SIZE);
	memset(buf,0,512);
	memset(sock->errbuff,0,EN_ERRBUFF_SIZE);
	snprintf(sock->errbuff, EN_ERRBUFF_SIZE-1, "[%u]%s", sock->errorcode, _ene_get_full_message(buf, 511, sock->errorcode));
	sock->errorcode=0;
	return sock->errbuff;
}

void en_aeskeys(esock_t sock, struct en_aes_key* write, struct en_aes_key* read)
{
	if(write!=NULL) en_get_aes_write_key(sock,write);
	if(read!=NULL)  en_get_aes_read_key( sock,read );
}

void en_get_rsa_local_publickey(esock_t sock, struct en_rsa_pub* local)
{
	en_publickeys(sock, local, NULL);
}

void en_get_rsa_remote_publickey(esock_t sock, struct en_rsa_pub* remote)
{
	en_publickeys(sock, NULL, remote);
}

void en_setflags(esock_t sock, unsigned int flags)
{
	sock->flags = flags;
	
	if(ISFLAG(flags, EN_SOCKFLAG_FORCEBLOCK)) _en_sockblock(sock->con, 0);
	else _en_sockblock(sock->con, 1);
}

unsigned int en_getflags(esock_t sock)
{
	return sock->flags;
}

void en_log(esock_t sock, ssize_t *r, ssize_t *w, int reset)
{
	if(r!=NULL) *r = sock->log_read;
	if(w!=NULL) *w = sock->log_written;
	if(reset) {
		sock->log_read = sock->log_written = 0;
	}
}

float en_version()
{
	return __VERSION;
}

void en_set_timeout(esock_t sock, long value)
{
	sock->fb_timeout = value;
}

long en_get_timeout(esock_t sock) {return sock->fb_timeout;}

/*
void en_test(const unsigned char *plain, int pl, struct en_aes_key key)
{
	char __buf[1024];
	char __kbuf[1024];
	EVP_CIPHER_CTX* ctx;
	
	memset(__buf,0,1024);
	memset(__kbuf,0,1024);
	
	printf("~~~~~ BEGIN TEST ~~~~~\r\n");
	printf("~[test]: Will encrypt plaintext \"%s\" with AES key %s\r\n", _en_hexstr(__buf, 1023, plain, pl), en_aes_f(__kbuf, 1023, &key));
	ctx = _en_aes_create(key.key,key.iv,1);
	if(!ctx)
	{
		printf("~[test]: _en_aes_create failed\r\n");
	}
	else {
		int rctl = pl%16==0?pl+16:_en_roundUp(pl, 16);
		int len;
		int ctl;
		unsigned char* ct = (unsigned char*)malloc(rctl);
		memset(ct,0,rctl);
		printf("~[test]: Allocated %d bytes for ciphertext (calculated from %d)\r\n", rctl, pl);
		if(EVP_EncryptUpdate(ctx, ct, &len, plain, pl))
		{
			ctl=len;
			printf("~[test]: First call returned len %d\r\n",ctl);
			if(EVP_EncryptFinal_ex(ctx, ct+len, &len))
			{
				ctl+=len;
				printf("~[test]: Second call returned len %d (+%d)\r\n", ctl, (ctl-len));
				if(ctl!=rctl) printf("~[test]: WARNING: Returned ciphertext length is not equal to expected\r\n");
				printf("~[test]: Ciphertext dump (%d bytes):", ctl);
  				BIO_dump_fp (stdout, (const char *)ct, ctl);
			}
			else {
				printf("~[test]: EVP_EncryptFinal_ex failed\r\n");
			}
		}
		else {
			printf("~[test]: EVP_EncryptUpdate failed\r\n");
		}
		EVP_CIPHER_CTX_free(ctx);
	}
	printf("~~~~~ END TEST ~~~~~\r\n");
}*/

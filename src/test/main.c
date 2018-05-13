#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>


#include <enet.h>

volatile _Atomic int running=1;

#define PORT 8999

#define PF_CLIENT "[client]:"
#define PF_SERVER "[server]:"

const int show_pd=0;

void hex2str(char* buf, int bs, const unsigned char* bytes, int num)
{
	register int i=0;
	char* nb = buf;
	for(;(i*2)<bs&&i<num;i++)
	{
		sprintf(nb, "%02x", bytes[i]);
		nb+=2;
	}
}

void printRSA(const char* begin, FILE* fp, RSA* rsa)
{
	char str[(SHA_DIGEST_LENGTH*2)+1];
	unsigned char thash[SHA_DIGEST_LENGTH];
	unsigned char hash[SHA_DIGEST_LENGTH+1024];
	char* buffer = (char*) (hash+SHA_DIGEST_LENGTH);
	int le;
	BIO* keybio = BIO_new(BIO_s_mem());
	RSA_print(keybio, rsa, 0);
	memset(hash,0,SHA_DIGEST_LENGTH+1024);
	while( (le=BIO_read(keybio, buffer, 1024)) > 0)
	{
		buffer[le]=0;
		
		if(fp)
		{
			fprintf(fp, "%s", buffer);
		}
		
		SHA1(hash, SHA_DIGEST_LENGTH+1024, thash);
		memcpy(hash, thash, SHA_DIGEST_LENGTH);
	}
	BIO_free(keybio);
	memset(str,0,(SHA_DIGEST_LENGTH*2)+1);
	hex2str(str, (SHA_DIGEST_LENGTH*2), hash, SHA_DIGEST_LENGTH);
	printf("%s%s", begin, str);
}



char* publicdatastr(char *buffer, int bs, esock_t sock, int remote)
{
	struct en_rsa_pub key;
	if(!remote)
	{
		en_publickeys(sock, &key, NULL);
	}
	else {	
		en_publickeys(sock, NULL, &key);
	}
	memset(buffer, 0, bs);
	return en_rsa_pub_f(buffer, bs, &key);
}

char* aesdatastr(char *buffer, int bs, esock_t sock, int read)
{
	struct en_aes_key key;
	if(!read)
	{
		en_get_aes_write_key(sock, &key);
	}
	else {
		en_get_aes_read_key(sock, &key);
	}
	memset(buffer,0,bs);
	return en_aes_f(buffer,bs, &key);
}

void printSHA1(char * begin, const void* _data, int ds)
{
	const unsigned char* data = (const unsigned char*)_data;
	unsigned char buf[SHA_DIGEST_LENGTH];
	char str[(SHA_DIGEST_LENGTH*2)+1];
	memset(str,0,(SHA_DIGEST_LENGTH*2)+1);
	SHA1(data, ds, buf);
	hex2str(str, (SHA_DIGEST_LENGTH*2), buf, SHA_DIGEST_LENGTH);
	printf("%s%s", begin, str);
}

void server_enc(int con)
{
	esock_t sock = en_create_socket(con, NULL);
	struct en_rsa_pub us,them;
	char _pd_buf[2048];
	char buffer[16];
	ssize_t l_r, l_w;
	FILE* keyfile = fopen("srv_key_local.txt", "w");
	
	en_addflag(sock, EN_SOCKFLAG_FORCEBLOCK); //enable force-blocking
	en_addflag(sock, EN_SOCKFLAG_LOG);
	
	en_set_timeout(sock, 5000); //set timeout to 5 seconds
	
	en_publickeys(sock, &us, NULL);
	printf(PF_SERVER " Socket created. Our RSA key is:\r\n");
	printRSA (PF_SERVER "\t[all](sha1)", keyfile, en_localRSA(sock));
	printf("\r\n");
	printSHA1(PF_SERVER "\t[pub](sha1)", &us, sizeof(struct en_rsa_pub));
	fclose(keyfile);
	printf("\r\n");
	if(show_pd) printf(PF_SERVER "\t(public data)%s\r\n", publicdatastr(_pd_buf, 2047, sock, 0));
	if( EN_SUCCESS == en_exchange(sock)) {
		FILE* rkf = fopen("srv_key_remote.txt", "w");
		
		en_publickeys(sock, NULL, &them);
		printf(PF_SERVER " exchange success, remote RSA is:\r\n");
		printRSA (PF_SERVER "\t[all](sha1)", rkf, en_remoteRSA(sock));
		printf("\r\n");
		printSHA1(PF_SERVER "\t[pub](sha1)", &them, sizeof(struct en_rsa_pub));
		fclose(rkf);
		printf("\r\n");
		if(show_pd) printf(PF_SERVER "\t(public data)%s\r\n", publicdatastr(_pd_buf, 2047, sock, 1));
	}
	else {printf(PF_SERVER " exchange failure: %s\r\n", en_error(sock));goto si_end;}
	
	sleep(1);
	if(en_set(sock, EN_READ, 1) == EN_SUCCESS)
	{
		char _pd_aes[2048];
		printf(PF_SERVER " en_set (READ) success\r\n");
		memset(_pd_aes,0,2048);
		printf(PF_SERVER "\tread AES key is:\t%s\r\n", aesdatastr(_pd_aes, 2047, sock ,1));
		
	}
	else {printf(PF_SERVER " en_set (READ) failure: %s\r\n", en_error(sock));goto si_end;}
	
	if(en_read(sock, buffer, 16)>0){
		buffer[15]=0;
		printf(PF_SERVER " Client sent message: \"%s\"\r\n", buffer);
	}
	else {
		printf(PF_SERVER " Read from socket failed: %s\r\n", en_error(sock));
		
  ERR_print_errors_fp(stderr);
		goto si_end;
	}
	en_set(sock, EN_READ, 0);
	
	en_log(sock, &l_r, &l_w, 1);
	printf(PF_SERVER " We read %d bytes and wrote %d bytes\r\n", (int)l_r, (int)l_w);
	sleep(1);
si_end:
	en_close(sock, 0);
}

void client_enc(int con)
{
	esock_t sock = en_create_socket(con, NULL);
	struct en_rsa_pub us,them;
	char _pd_buf[2048];
	char buffer[16];
	ssize_t l_r,l_w;
	FILE* keyfile = fopen("cli_key_local.txt", "w");
	
	en_addflag(sock, EN_SOCKFLAG_FORCEBLOCK);
	en_addflag(sock, EN_SOCKFLAG_LOG);
	
	en_publickeys(sock, &us, NULL);
	printf(PF_CLIENT " Socket created. Our RSA key is:\r\n");
	printRSA(PF_CLIENT "\t[all](sha1)",keyfile, en_localRSA(sock));
	printf("\r\n");
	printSHA1(PF_CLIENT "\t[pub](sha1)", &us, sizeof(struct en_rsa_pub));
	fclose(keyfile);
	printf("\r\n");
	if(show_pd) printf(PF_CLIENT "\t(public data)%s\r\n", publicdatastr(_pd_buf, 2047, sock, 0));
	if( EN_SUCCESS == en_exchange(sock)) {
		FILE* rkf = fopen("cli_key_remote.txt", "w");
		
		en_publickeys(sock, NULL, &them);
		printf(PF_CLIENT " exchange success, remote RSA is:\r\n");
		printRSA(PF_CLIENT "\t[all](sha1)", rkf, en_remoteRSA(sock));
		printf("\r\n");
		printSHA1(PF_CLIENT "\t[pub](sha1)", &them, sizeof(struct en_rsa_pub));
		fclose(rkf);
		printf("\r\n");
		if(show_pd) printf(PF_CLIENT "\t(public data)%s\r\n", publicdatastr(_pd_buf, 2047, sock, 1));
		
	} else {printf(PF_CLIENT " exchange failure: %s\r\n", en_error(sock));goto ci_end;}
	
	if(en_set(sock, EN_WRITE, 1) == EN_SUCCESS)
	{
		char _pd_aes[2048];
		printf(PF_CLIENT " en_set (WRITE) success\r\n");
		memset(_pd_aes,0,2048);
		printf(PF_CLIENT "\twritten AES key is:\t%s\r\n", aesdatastr(_pd_aes, 2047, sock , 0));
	}
	else {printf(PF_CLIENT " en_set (WRITE) failure: %s\r\n", en_error(sock)); goto ci_end;}
	
	memset(buffer,0,16);
	snprintf(buffer, 15, "Hello, world!");
	
	if(en_write(sock, buffer, 16)>0)
	{
		printf(PF_CLIENT " Successfully sent message to server\r\n");
	}
	else {
		printf(PF_CLIENT " Failed writing message to server: %s\r\n", en_error(sock));
		goto ci_end;
	}
	
	en_set(sock, EN_WRITE, 0);
	
	en_log(sock, &l_r, &l_w, 1);
	printf(PF_CLIENT " We read %d bytes and wrote %d bytes\r\n", (int)l_r, (int)l_w);
	sleep(10);
ci_end:
	en_close(sock, 0);
}

void * cliw(void* _)
{
	int sock = socket(AF_INET , SOCK_STREAM , 0);	
	struct sockaddr_in server;
	
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
    	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	sleep(1);
	if (connect(sock, (struct sockaddr *)&server , sizeof(server)) == 0) {
		printf(PF_CLIENT " Connection success\r\n");
		client_enc(sock);
		//close(sock);
	} else {
		printf(PF_CLIENT " Connection failure\r\n");
		return NULL;
	}
	printf(PF_CLIENT " Connection closed\r\n");
	return NULL;
}

void * srvw(void * _)
{
	struct sockaddr_in addr;
	pthread_t cli;
	struct sockaddr client_addr;
	socklen_t client_addr_len;
	int cs;
	
	int s = socket(AF_INET, SOCK_STREAM, 0);
	
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(PORT);
	
	
	bind(s, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
	listen(s, 5);
	
	printf(PF_SERVER " Listening...\r\n");
	
	pthread_create(&cli, NULL, &cliw, NULL);
	
	if( (cs = accept(s, &client_addr, &client_addr_len)) )
	{
		printf(PF_SERVER " Connection success\r\n");
		server_enc(cs);
		//close(cs);
	}
	printf(PF_SERVER " Connection closed\r\n");
	close(s);
	running=0;
	
	return NULL;
}

/*void cryptotest()
{
	char string[] = "Test string";
	struct en_aes_key key;
	
	RAND_bytes((unsigned char*)&key, sizeof(struct en_aes_key));
	
	en_test((unsigned char*)string, strlen(string), key);
}*/

void extc_read(esock_t sock)
{
	int32_t rd;
	int rrd;
	char *buf;
	if(en_read(sock, &rd, sizeof(int32_t))>0) {
		printf("[read]: Allocating %d+1 bytes for read\r\n", rd);
		buf = (char*)malloc(rd+1);
		memset(buf,0,rd+1);
		
		if( (rrd=en_read(sock, buf, rd))<=0)
			printf("[read]: Read failed: %s\r\n", en_error(sock));
		else
			printf("[read]: Received string (%d bytes [expected %d]) \"%s\"\r\n", rrd, rd, buf);
		free(buf);
		printf("[read]: Done\r\n");
	}
	else printf("[read]: Read size failed: %s\r\n", en_error(sock));
}

void extc_write(esock_t sock)
{
	char* buf= "TEST STRING FROM CLIENT";
	int32_t sz = strlen(buf);
	
	en_write(sock, &sz, sizeof(int32_t));
	en_write(sock, buf, sz);
}

void extc(esock_t sock)
{
	if(en_exchange(sock)==EN_SUCCESS)
	{
		printf("Exchange success\r\n");
		
		if(en_set(sock, EN_WRITE, 1)==EN_SUCCESS) {
			printf("Set write success\r\n");
			extc_write(sock);
			printf("Write data complete\r\n");
			en_set(sock, EN_WRITE, 0);
			if(en_set(sock, EN_READ, 1)==EN_SUCCESS)
			{
				
				printf("Set read success\r\n");
				extc_read(sock);
				printf("Read data complete\r\n");
				en_set(sock, EN_READ, 0);
			
			} else printf("Set read error: %s\r\n", en_error(sock));
		} else printf("Set write error: %s\r\n", en_error(sock));
		
	}
	else {
		printf("Exchange error: %s\r\n", en_error(sock));
	}
}

int main(int argc, char** argv)
{
	pthread_t srv;
	printf("Test of libenet v%.1f\r\n\r\n", en_version());
	if(argv[1]!=NULL&&strcmp(argv[1], "-con")==0) // Connect to remote host then do the following: exchange keys, set write context, write length of string (int32_t), write string, free write context, set read context, read length of string, read string, free read context, close connection.
	{
		int sock = socket(AF_INET , SOCK_STREAM , 0);	
		struct sockaddr_in server;
		
		server.sin_addr.s_addr = inet_addr(argv[2]);
	    	server.sin_family = AF_INET;
		server.sin_port = htons(9090);
		if (connect(sock, (struct sockaddr *)&server , sizeof(server)) == 0) {
			esock_t es = en_create_socket(sock, NULL);
			extc(es);
			printf("Done, last error on socket was \"%s\"\r\n", en_error(es));
			en_close(es, 0);
		}
		else printf("Connection failed\r\n");
		
		return 0;
	}
	
	/* Client server model test */
	
	pthread_create(&srv, NULL, &srvw, NULL);
	
	while(running) sleep(1);
	printf("[MAIN]: Exiting\r\n");
	return 0;
}

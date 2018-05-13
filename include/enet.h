#ifndef _ENET_H
#define _ENET_H
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <setjmp.h>

#define _EN_CUSTOM_CRC //internal macro used for building. If this is off you'll need to link with -lz as well, and there may be compatability issues.

#define EN_CLOSE_KEEPALIVE 1 /* Keep socket connection alive */
#define EN_CLOSE_KEEPRSA   2 /* Keep RSA object alive */

#define EN_RSA_KEYSIZE 1024
#define EN_RSA_EXP 0x010001

#define EN_RSAP_MODSIZE 128
#define EN_RSAP_EXPSIZE 3

#define EN_AESP_KEYSIZE 32
#define EN_AESP_IVSIZE 16

#define EN_SUCCESS 0
#define EN_FAILURE 1

#define EN_CRC32_SEED 0xffffffffu

#define EN_READ 	1 /* Controls en_read() calls (pass to en_set()) */
#define EN_WRITE	2 /* Controls en_write() calls (pass to en_set()) */

#define ENE_SREAD_ERROR			(1<<8)

#define ENE_SREAD_INCORRECT_SIZE 	(ENE_SREAD_ERROR|(1<<0))
#define ENE_SREAD_INVALID_CHECKSUM 	(ENE_SREAD_ERROR|(1<<1))
#define ENE_SREAD_SSL_FAILURE		(ENE_SREAD_ERROR|(1<<2))
#define ENE_SREAD_AES_FAILURE		(ENE_SREAD_ERROR|(1<<3))
#define ENE_SREAD_ALREADY_AQUIRED	(ENE_SREAD_ERROR|(1<<4))

#define ENE_RSAE_ERROR			(1<<9)

#define ENE_RSAE_INCORRECT_SIZE		(ENE_RSAE_ERROR|(1<<0))
#define ENE_RSAE_INVALID_CHECKSUM	(ENE_RSAE_ERROR|(1<<1))
#define ENE_RSAE_WRITE_FAIL		(ENE_RSAE_ERROR|(1<<2))

#define ENE_SET_ERROR			(1<<10)

#define ENE_SET_UNKNOWN_FLAG		(ENE_SET_ERROR|(1<<0))

#define ENE_SWRITE_ERROR		(1<<11)

#define ENE_SWRITE_SSL_FAILURE		(ENE_SWRITE_ERROR|(1<<0))
#define ENE_SWRITE_AES_FAILURE		(ENE_SWRITE_ERROR|(1<<1))
#define ENE_SWRITE_KEYGEN_FAILURE	(ENE_SWRITE_ERROR|(1<<2))
#define ENE_SWRITE_ALREADY_AQUIRED	(ENE_SWRITE_ERROR|(1<<3))

#define ENE_USREAD_ERROR		(1<<12)

#define ENE_USREAD_NOT_AQUIRED		(ENE_USREAD_ERROR|(1<<0))

#define ENE_USWRITE_ERROR		(1<<13)

#define ENE_USWRITE_NOT_AQUIRED		(ENE_USWRITE_ERROR|(1<<0))

#define ENE_WRITE_ERROR			(1<<14)

#define ENE_WRITE_AES_RELOAD_FAIL	(ENE_WRITE_ERROR|(1<<0))
#define ENE_WRITE_AES_UPDATE_FAIL	(ENE_WRITE_ERROR|(1<<1))
#define ENE_WRITE_AES_FINAL_FAIL	(ENE_WRITE_ERROR|(1<<2))
#define ENE_WRITE_FAIL			(ENE_WRITE_ERROR|(1<<3))

#define ENE_READ_ERROR			(1<<15)

#define ENE_READ_AES_RELOAD_FAIL	(ENE_READ_ERROR|(1<<0))
#define ENE_READ_AES_UPDATE_FAIL	(ENE_READ_ERROR|(1<<1))
#define ENE_READ_AES_FINAL_FAIL		(ENE_READ_ERROR|(1<<2))
#define ENE_READ_INCORRECT_SIZE		(ENE_READ_ERROR|(1<<3))
#define ENE_READ_TIMEOUT		(ENE_READ_ERROR|(1<<4))

#define ENE_FATAL_ERROR			(1<<16)
#define ENE_FATAL_HEAP_CORRUPTION	(ENE_FATAL_ERROR|(1<<0))


#define EN_SOCKFLAG_LOG			(1<<0) /* Log all reads and writes (can be accessed with en_log()) */
#define EN_SOCKFLAG_NOCHECKSUM		(1<<1) /* Do not check data integrity */
#define EN_SOCKFLAG_FORCEBLOCK		(1<<2) /* Force reads to block until all data has been read or a timeout is reached (default 0: no timeout) */
#define EN_SOCKFLAG_NO_HTON		(1<<3) /* Do not swap byte orders */

#define en_addflag(sock, f) en_setflags(sock, en_getflags(sock)|f)

typedef struct esock_t* esock_t;

struct en_rsa_pub {
	unsigned char mod[EN_RSAP_MODSIZE];
	unsigned char exp[EN_RSAP_EXPSIZE];
};

struct en_aes_key {
	unsigned char key[EN_AESP_KEYSIZE];
	unsigned char iv[EN_AESP_IVSIZE];
};

/*** API FUNCTIONS ***
 * Most int functions return EN_SUCCESS on success and EN_FAILURE on failure unless otherwise noted.
 * Error reporting ***should*** be thread-safe, although I haven't tested it (subsequent calls to en_error() on the same socket will rewrite the internal buffer and could give incorrect results in a race condition)
***/

esock_t		en_create_socket(int con, RSA *rsa); /* Create new encrypted socked from socket `con' and RSA `rsa'.  If `rsa' is NULL, a new key will be generated */
void		en_close(esock_t s, int flags);	/* Close and release all reources used by `s', with possible options EN_CLOSE_*.  This will also free any cipher contexts that are still allocated.  */
int		en_exchange(esock_t sock); /* Exchange RSA keys with remote host */
int		en_set(esock_t sock, int flag, int on); /* Set EN_READ and/or EN_WRITE either enabled (1) or disabled (0) */
int		en_get(esock_t sock, int flag); /* Check if EN_READ and/or EN_WRITE is set to encrypt */
ssize_t		en_write(esock_t sock, void* buf, size_t count); /* Write `count' no. of bytes of `buf' to `sock'. Returns >0 on success. */
ssize_t		en_read(esock_t sock, void* buf, size_t count); /* Read `count' no. of bytes from `sock' to `buf'. Returns >0 on success. */
void		en_aeskeys(esock_t sock, struct en_aes_key* write, struct en_aes_key* read); /* Get current AES keys used.  This will likely segfault if they are not set, so check that yourself (maybe I should fix this?).  NULL arguments are ignored.  */
void		en_get_aes_read_key(esock_t sock, struct en_aes_key* key); /* Same as en_aeskeys(sock,NULL,key) */
void		en_get_aes_write_key(esock_t sock, struct en_aes_key* key); /* Same as en_aeskeys(sock,key,NULL) */
const char*	en_error(esock_t sock); /* Get last error string reported to `sock'. The pointer is to an internal buffer that may change whenever this function is called */
RSA*		en_localRSA(esock_t sock); /* Return local RSA object */
RSA*		en_remoteRSA(esock_t sock); /* Return remote RSA object */
EVP_CIPHER_CTX* en_writeAES(esock_t sock); /* Return cipher context for write AES (NULL if not set) */
EVP_CIPHER_CTX* en_readAES(esock_t sock); /* Return cipher context for read AES (NULL if not set) */
void		en_publickeys(esock_t sock, struct en_rsa_pub *local, struct en_rsa_pub *remote); /* Get current RSA public keys used.  This will likely segfault if you have not exchagend RSA keys with remote host. */
void		en_get_rsa_local_publickey(esock_t sock, struct en_rsa_pub* local); /* Same as en_publickeys(sock, key, NULL) */
void		en_get_rsa_remote_publickey(esock_t sock, struct en_rsa_pub* remote); /* Same as en_publickeys(sock, NULL, key) */
char*		en_rsa_pub_f(char* buffer, int bs, const struct en_rsa_pub *key); /* Convert the en_rsa_pub key to a readable string in buffer `buffer'.  */
char*		en_aes_f(char* buffer, int bs, const struct en_aes_key *key); /* Convert the en_aes_key to a readable string in buffer `buffer'.  */
void		en_setflags(esock_t sock, unsigned int flags); /* Set special flags for `sock'.  See EN_SOCKFLAG_* macros above.  */
unsigned int	en_getflags(esock_t sock); /* Get flags for `sock' */
void		en_log(esock_t sock, ssize_t *r, ssize_t *w, int reset); /* Get the log data (EN_SOCKFLAG_LOG) from `sock'.  If `r' or `w' is NULL, it is ignored.  If `reset' is nonzero the internal values will then be reset.  */
float		en_version(); /* Return build version (defined in file "VERSION"). */
void		en_set_timeout(esock_t sock, long value); /* Set the force-block timeout  (in miliseconds) (0 for infinite) */
long		en_get_timeout(esock_t sock); /* Get the force-block timeout (default 0: infinite) */
void		en_seterrjmp(esock_t sock, jmp_buf *buffer); /* Set longjmp on error (or NULL). setjmp() value will be the error code.  After a jump to this buffer, the pointer is reset to NULL. */

#endif /* _ENET_H */

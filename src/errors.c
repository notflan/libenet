#include <enet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <internal/errors.h>

typedef struct {
	_en_ecode_t code;
	const char* desc;
} _en_error_t;

_en_error_t _en_errors[] = {
	{ENE_SREAD_ERROR, "(ENE_SREAD_ERROR)"},
	{ENE_SREAD_INCORRECT_SIZE, "Could not read correct number of bytes from stream"},
	{ENE_SREAD_INVALID_CHECKSUM, "Checksum mismatch"},
	{ENE_SREAD_SSL_FAILURE, "RSA decryption failed"},
	{ENE_SREAD_AES_FAILURE, "Could not aquire AES EVP cipher context"},
	{ENE_SREAD_ALREADY_AQUIRED, "Context already aquired (call en_set(sock, EN_READ, 0) first)"},
	
	{ENE_RSAE_ERROR, "(ENE_RSAE_ERROR)"},
	{ENE_RSAE_INCORRECT_SIZE, "Could not read correct number of bytes from stream"},
	{ENE_RSAE_INVALID_CHECKSUM, "Checksum mismatch"},
	{ENE_RSAE_WRITE_FAIL, "Could not write correct number of bytes to stream"},
	
	{ENE_SET_ERROR, "(ENE_SET_ERROR)"},
	{ENE_SET_UNKNOWN_FLAG, "Unknown flag"},
	
	{ENE_SWRITE_ERROR, "(ENE_SWRITE_ERROR)"},
	{ENE_SWRITE_SSL_FAILURE, "RSA encryption failed"},
	{ENE_SWRITE_AES_FAILURE, "Could not aquire AES EVP cipher context"},
	{ENE_SWRITE_KEYGEN_FAILURE, "Could not generate random bytes for AES key"},
	{ENE_SWRITE_ALREADY_AQUIRED, "Context already aquired (call en_set(sock, EN_WRITE, 0) first)"},
	
	{ENE_USREAD_ERROR, "(ENE_USREAD_ERROR)"},
	{ENE_USREAD_NOT_AQUIRED, "Context is not aquired"},
	
	{ENE_USWRITE_ERROR, "(ENE_USWRITE_ERROR)"},
	{ENE_USWRITE_NOT_AQUIRED, "Conext is not aquired"},
	
	{ENE_WRITE_ERROR, "(ENE_WRITE_ERROR)"},
	{ENE_WRITE_AES_RELOAD_FAIL, "Could not re-aquire AES EVP cipher context after encryption"},
	{ENE_WRITE_AES_UPDATE_FAIL, "Encryption failed on first transform"},
	{ENE_WRITE_AES_FINAL_FAIL, "Encryption failed on last transform (finalisation)"},
	{ENE_WRITE_FAIL, "Could not write full buffer (partial writes are not supported)"},
	
	{ENE_READ_ERROR, "(ENE_READ_ERROR)"},
	{ENE_READ_AES_RELOAD_FAIL, "Could not re-aquire AES EVP cipher context after decryption"},
	{ENE_READ_AES_UPDATE_FAIL,  "Decryption failed on first transform"},
	{ENE_READ_AES_FINAL_FAIL, "Decryption failed on last transform (finalisation)"},
	{ENE_READ_INCORRECT_SIZE, "Could not read full buffer (partial reads are not supported)"},
	{ENE_READ_TIMEOUT, "Read timeout was reached"},
	
	{ENE_FATAL_ERROR, "(ENE_FATAL_ERROR)"},
	{ENE_FATAL_HEAP_CORRUPTION, "Heap corruption likely on decrypt call"},
	
	{0,NULL},
};

static const char* __ene_lookup(_en_ecode_t code)
{
	register int i=0;
	for(;_en_errors[i].desc!=NULL; i++)
	{
		if(_en_errors[i].code == code) return _en_errors[i].desc;	
	}
	return NULL;
}

const char* _ene_get_header_message(_en_ecode_t code)
{
	unsigned int tr = (code>>8)<<8;
	return __ene_lookup(tr);
}

const char* _ene_get_detailed_message(_en_ecode_t code)
{
	return __ene_lookup(code);
}

char* _ene_get_full_message(char *buf, int bs, _en_ecode_t code)
{
	//static char buf[512];
	const char* h;
	const char* d;
	memset(buf,0,bs);

	h = _ene_get_header_message(code);
	d = _ene_get_detailed_message(code);

	snprintf(buf, bs-1, "%s: %s", (h==NULL?"(unbound)":h), (d==NULL?"(unbound)":d));			
	return buf;
}

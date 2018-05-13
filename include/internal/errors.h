#ifndef _ERRORS_H
#define _ERRORS_H
#include <stdatomic.h>

typedef _Atomic unsigned int _en_ecode_t;

const char* _ene_get_header_message(_en_ecode_t code);
const char* _ene_get_detailed_message(_en_ecode_t code);
char* _ene_get_full_message(char *buf, int bs, _en_ecode_t code);

#endif /* _ERRORS_H */

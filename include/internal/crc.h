#ifndef _CRC_H
#define _CRC_H
#include <stdint.h>
#include <stdatomic.h>

#define _EN_CRC_TABLE_SIZE 256
#define _EN_CRC_ITERATIONS 8

unsigned long _en_crc32(unsigned long seed, const unsigned char* buffer,unsigned int len);

#endif /* _CRC_H */

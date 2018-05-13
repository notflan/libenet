#include <internal/crc.h>

static const uint32_t __en_crc_poly = 0xedb88320u;

static uint32_t __en_crc_table[_EN_CRC_TABLE_SIZE];
static _Atomic volatile int __en_crc_initialised=0;

static _Atomic volatile int __initialising=0;

static uint32_t* __en_crc_create_table(uint32_t* table, uint32_t poly)
{
	register int i=0;
	for(;i<_EN_CRC_TABLE_SIZE;i++)
	{
		register int j=0;
		uint32_t e = (uint32_t)i;
		for(;j<_EN_CRC_ITERATIONS;j++)
		{
			if( (e&1) == 1)
				e = (e>>1) ^ poly;
			else e = e>>1;
		}
		table[i] = e;
	}
	return table;
}

static uint32_t __en_crc_calc(uint32_t* table, uint32_t seed,  const unsigned char* buffer, int len)
{
	uint32_t crc= seed;
	register int i=0;
	for(;i<len;i++)
	{
		crc = (crc>>8) ^ table[(buffer[i] ^ crc) & 0xff];
	}
	return crc;
}

unsigned long _en_crc32(unsigned long seed, const unsigned char* buffer,unsigned int len)
{
	while(__initialising) (void)0;
	
	if(!__en_crc_initialised)
	{
		__initialising=1;
		__en_crc_create_table(__en_crc_table,__en_crc_poly);
		__en_crc_initialised=1;
		__initialising=0;
		
	}
	return ~__en_crc_calc(__en_crc_table, (uint32_t) seed, buffer, (int)len);
}

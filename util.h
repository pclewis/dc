#include <stdint.h>

#define BIT(i)      (1<<(i))
#define BIT_IS_SET(v,i) ((v&BIT(i))!=0)

static inline uint8_t reverseBits(uint8_t b) {// hax
	return ((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16; 
}

void die(const char *fmt, ...);
size_t fread_safe(void *ptr, size_t size, size_t nmemb, FILE *stream);
FILE *confirmOpen(const char *fn, const char *mode);
void writeFile(const char *desc, FILE *fp, void *data, size_t size);
long fileSize(FILE *fp);

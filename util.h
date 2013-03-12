#include <stdint.h>

#ifndef __GNUC__
#define __attribute__(x)
#endif

#define BIT(i)      (1<<(i))
#define BIT_IS_SET(v,i) ((v&BIT(i))!=0)

static inline uint8_t reverseBits(uint8_t b) {// hax
	return ((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16; 
}

void die(const char *fmt, ...) __attribute__((noreturn, nonnull (1), format (printf, 1, 2)));
size_t fread_safe(void *ptr, size_t size, size_t nmemb, FILE *stream) __attribute__((nonnull));
FILE *fopen_safe(const char *fn, const char *mode) __attribute__((nonnull));
size_t fwrite_safe(FILE *fp, void *data, size_t size) __attribute__((nonnull));
long fileSize(FILE *fp) __attribute__((nonnull));
void *realloc_safe(void *ptr, size_t size);
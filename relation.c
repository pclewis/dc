#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "util.h"

#define MAX_KEY_SIZE 240

typedef struct {
	int cnt[MAX_KEY_SIZE][8][2];
	uint8_t value[MAX_KEY_SIZE][8][2][MAX_KEY_SIZE];
	uint8_t related[MAX_KEY_SIZE][8][2][MAX_KEY_SIZE];
} Relation;

void memxorv(uint8_t *dst, uint8_t v, size_t size) {
	uint8_t *e = dst+size;
	while (dst<e) *dst++ ^= v;
}

void memxor(uint8_t *dst, const uint8_t *src, size_t size) {
	uint8_t *e = dst+size;
	while (dst<e) *dst++ ^= *src++;
}

void memand(uint8_t *dst, const uint8_t *src, size_t size) {
	uint8_t *e = dst+size;
	while (dst<e) *dst++ &= *src++;
}

char *scrambleFileName(const char *fn) {
	static char sfn[FILENAME_MAX+1];
	strncpy(sfn, fn, FILENAME_MAX);
	size_t i = strlen(sfn);
	sfn[i-3] = 's';
	sfn[i-2] = 'c';
	sfn[i-1] = 'r';
	return sfn;
}

void relate(Relation *relation, const char *fn) {
	FILE *keyfp = fopen_safe(fn, "rb");
	FILE *scrfp = fopen_safe(scrambleFileName(fn), "rb");
	if(!keyfp) return;
	if(!scrfp) { fclose(keyfp); return; }
	uint8_t key[MAX_KEY_SIZE], scr[MAX_KEY_SIZE];
	size_t keySize = 0, scrSize = 0;

	keySize = fread(key, 1, MAX_KEY_SIZE, keyfp);
	scrSize = fread(scr, 1, MAX_KEY_SIZE, scrfp);

	fclose(keyfp); fclose(scrfp);

	if(keySize != scrSize) {
		fprintf(stderr, "Different key sizes: %zu %zu\n", keySize, scrSize);
		return;
	}

	if(keySize == 0) {
		fprintf(stderr, "Key size 0, skipping %s\n", fn);
		return;
	}

	size_t oks = keySize;
	while (keySize < MAX_KEY_SIZE) {
		memcpy(key+keySize, key, oks);
		memcpy(scr+keySize, scr, oks);
		keySize += oks;
	}

	for(size_t i = 0; i < keySize; ++i) {
		for(int b = 0; b < 8; ++b) {
			int bs = BIT_IS_SET(key[i], b) ? 1 : 0;

			if(relation->cnt[i][b][bs]++ > 0) {
				uint8_t buf[MAX_KEY_SIZE];
				memcpy(buf, scr, MAX_KEY_SIZE);
				memxor(buf, relation->value[i][b][bs], MAX_KEY_SIZE);
				memand(relation->related[i][b][bs], buf, MAX_KEY_SIZE);
			} else {
				memcpy(relation->value[i][b][bs], scr, MAX_KEY_SIZE);
				memset(relation->related[i][b][bs], 0xFF, MAX_KEY_SIZE);
			}
		}
	}
}

int main(int argc, char *argv[]) {
	int status = EXIT_FAILURE;
	if(argc < 3) {
		printf("Usage: %s keyfile...\n", argv[0]);
		goto done;
	}

	Relation *relation = calloc(1, sizeof(Relation));

	for(int i = 1; i < argc; ++i) {
		relate(relation, argv[i]);
	}

	for(size_t ki = 0; ki < MAX_KEY_SIZE; ++ki) {
		for(int bi = 0; bi < 8; ++bi) {
			for(int bv = 0; bv < 2; ++bv) {
				if( relation->cnt[ki][bi][bv] < 2) {
					printf("Didn't see enough key index %zu bit %d with value %d\n", ki, bi, bv);
					continue;
				}
				for(size_t si = 0; si < MAX_KEY_SIZE; ++si) {
					for(int sb = 0; sb < 8; ++sb) {
						if(BIT_IS_SET( relation->related[ki][bi][bv][si], sb ))
							printf("key %zu bit %d = %d, scr %zu bit %d = %d, cnt=%d\n", ki, bi, bv, si, sb, BIT_IS_SET(relation->value[ki][bi][bv][si], sb) ? 1 : 0, relation->cnt[ki][bi][bv]);
					}
				}
			}
		}
	}
	printf("Welp.\n");

	status = EXIT_SUCCESS;

	done:
	return status;
}
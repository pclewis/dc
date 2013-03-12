#include <stdio.h>
#include <stdlib.h>

FILE *confirmOpen(const char *fn, const char *mode) {
	FILE *fp = fopen(fn, mode);
	if(!fp) perror(fn);
	return fp;
}

static inline unsigned char reverseBits(unsigned char b) {// hax
	return ((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16; 
}

int main(int argc, char *argv[]) {
	int status = EXIT_FAILURE;
	FILE *f1 = NULL;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s [f1]\n", argv[0]);
		goto done;
	}

	f1 = confirmOpen(argv[1], "rb");

	if(!f1) goto done;

	int c;
	while((c = fgetc(f1)) != EOF) {
		fputc( (unsigned char)reverseBits(c), stdout );
	}

	status = EXIT_SUCCESS;

done:
	if(f1) fclose(f1);
	return status;
}
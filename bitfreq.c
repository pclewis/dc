#include <stdio.h>
#include <stdlib.h>

#define BIT(i)      (1<<(i))
#define BIT_IS_SET(v,i) ((v&BIT(i))!=0)

FILE *confirmOpen(const char *fn, const char *mode) {
	FILE *fp = fopen(fn, mode);
	if(!fp) perror(fn);
	return fp;
}

int main(int argc, char *argv[]) {
	int status = EXIT_FAILURE;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s [f1]\n", argv[0]);
		goto done;
	}

	FILE *f1 = confirmOpen(argv[1], "rb");

	if(!f1) goto done;

	unsigned int setBits = 0, totalBits = 0, sb[8] = {0}, ub[8] = {0}; 

	int c;
	int b;
	while((c = fgetc(f1)) != EOF) {
		for(b = 0; b < 8; ++b) {
			if (BIT_IS_SET(c, b)) {
				sb[b]++;
				setBits++;
			} else {
				ub[b]++;
			}
			totalBits++;
		}
	}

	for(b = 0; b < 8; ++b) {
		printf("Bit %d: %8u %8u\n", b, ub[b], sb[b]);
	}

	printf("       %8u %8u (%u)\n", totalBits - setBits, setBits, totalBits);

	status = EXIT_SUCCESS;

done:
	if(f1) fclose(f1);
	return status;
}
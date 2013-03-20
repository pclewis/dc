#include <stdio.h>
#include <stdlib.h>
#include "util.h"

int main(int argc, char *argv[]) {
	int status = EXIT_FAILURE;
	FILE *f1 = NULL;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s [f1]\n", argv[0]);
		goto done;
	}

	f1 = fopen_safe(argv[1], "rb");

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
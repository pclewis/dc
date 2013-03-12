#include <stdio.h>
#include <stdlib.h>
#include "util.h"

int main(int argc, char *argv[]) {
	int status = EXIT_FAILURE;
	FILE *f1 = NULL, *f2 = NULL;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s [f1] [f2]\n", argv[0]);
		goto done;
	}

	f1 = fopen_safe(argv[1], "rb");
	f2 = fopen_safe(argv[2], "rb");

	if(!f1 || !f2) goto done;

	while(1) {
		int c1 = fgetc(f1), c2 = fgetc(f2);
		if(c1 == EOF || c2 == EOF) break;
		fputc( (unsigned char)(c1 ^ c2), stdout );
	}

	status = EXIT_SUCCESS;

done:
	if(f1) fclose(f1);
	if(f2) fclose(f2);
	return status;
}
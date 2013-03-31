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

	int c;
	while((c = fgetc(f1)) != EOF) {
		int c2 = fgetc(f1);
		if(c2 != EOF) fputc(c2, stdout);
		fputc( c, stdout );
	}

	status = EXIT_SUCCESS;

done:
	if(f1) fclose(f1);
	return status;
}
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

#define BLOCK_SIZE  0x1E00
#define BITRATE     128000
#define FREQUENCY   44100
#define FRAME_SIZE  144 * BITRATE / FREQUENCY
#define LOOP_OFFSET 0xF000 // I don't actually understand this value

void die(char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	exit(EXIT_FAILURE);
}

size_t findFirstFrameHeader(uint8_t *data) {
	for(size_t i = 0; i < 32; ++i) {
		if( data[i] == data[LOOP_OFFSET+i] &&
			data[i+1] == data[LOOP_OFFSET+i+1]) {
			return i;
		}
	}

	die("Could not find first frame header");
	return (size_t)-1;
}

int main(int argc, char *argv[]) {
	if(argc < 2) { 
		fprintf(stderr, "Usage: %s <file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	FILE *fp = fopen(argv[1], "rb");
	if(fp == NULL) {
		perror("Couldn't open file");
		return EXIT_FAILURE;
	}

	void *data = malloc( ftell(fp) );
	fread(data, ftell(fp), 1, fp);
	fclose(fp);


	size_t firstFrameHeader = findFirstFrameHeader(data);

	printf("Found first frame at %zu\n", firstFrameHeader);

	return EXIT_SUCCESS;
}




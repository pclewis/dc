#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

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

size_t findNextFrameHeader(uint8_t *data, size_t size, size_t start) {
	size_t i = 0;

	for(i = start; i < size; ++i) {
		if( data[i] == data[LOOP_OFFSET+i] && data[i+1] == data[LOOP_OFFSET+i+1]) {
			uint8_t b1 = data[i], b2 = data[i+1];
			bool found = true;
			for(size_t j = i + LOOP_OFFSET; j < size; j += LOOP_OFFSET) {
				if(data[j] != b1 || data[j+1] != b2) {
					found = false;
					break;
				}
			}
			if(found) break;
		}
	}

	return i;
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

	size_t size = ftell(fp);
	void *data = malloc( size );
	fread(data, size, 1, fp);
	fclose(fp);


	size_t firstFrameHeader = findNextFrameHeader(data, size, 0);
	size_t secondFrameHeader = findNextFrameHeader(data, size, firstFrameHeader+FRAME_SIZE);

	printf("Found first frame at %zu\n", firstFrameHeader);
	printf("Found second frame at %zu\n", secondFrameHeader);

	return EXIT_SUCCESS;
}




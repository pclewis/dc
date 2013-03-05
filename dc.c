#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

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
	fprintf(stderr, "\n");

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

void swapBytes(uint8_t *data, size_t size) {
	for(size_t i = 0; i < size-2; i += 2) {
		uint8_t tmp = data[i];
		data[i] = data[i+1];
		data[i+1] = tmp;
	}
}

bool counterBitsMatch( uint8_t c, uint16_t d, size_t start, size_t end ) {
	assert( start <= 8 );
	assert( end   <= 8 );
	assert( start < end );

	for(size_t bitNum = start; bitNum < end; ++bitNum) {
		bool cbit = (c & (1 << bitNum)) != 0;
		bool dbit1 = (d & (1 << (bitNum * 2)));
		bool dbit2 = (d & (1 << (bitNum * 2 + 1)));
		if(cbit != dbit1 && cbit != dbit2) {
			//printf("Counter bit doesnt match: %d (%04x) bit %d (%d %d %d)\n", c, d, bitNum, cbit, dbit1, dbit2);
			return false;
		}
	}
	return true;
}

bool counterWorks(uint8_t counter, uint16_t *data16, size_t offset) {
	size_t i = offset/2; // index into data16
	uint8_t c = counter + ((offset % 0x1E00) / 2); // adjust counter for offset

	if((offset%2) == 0) {
		return counterBitsMatch( c, data16[i] ^ 0xFFFB, 0, 8 );
	} else {
		return counterBitsMatch( c, data16[i] ^ 0x00FF, 4, 8 ) && counterBitsMatch( c, data16[i+1] ^ 0xFB00, 0, 4 );;
	}
}

uint8_t determineCounter(uint8_t *data, size_t size) {
	uint8_t result = 0;
	for(uint16_t counter = 0; counter <= 255; ++counter) {
		size_t i = 0;
		bool works = true;
		while(i < LOOP_OFFSET && i < size) {
			i = findNextFrameHeader(data, size, i);
			if(!counterWorks(counter, data, i)) {
				if(i > 12) {
					printf("%d abandonded at %d\n", counter, i);
				}
				works = false;
				break;
			}
			i += FRAME_SIZE;
		}

		if(works) {
			printf("Found possible counter: %u\n", counter);
			result = counter;
		}
	}

	return result;
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

	fseek(fp, 0, SEEK_END);
	size_t size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	void *data = malloc( size );

	size_t readBytes = fread(data, 1, size, fp);
	if(readBytes < size) {
		die("Read %zu of %zu bytes", readBytes, size);
	}
	fclose(fp);

	printf("Swapping bytes\n");
	swapBytes(data, size);


	void *scramblePattern = calloc(1, BLOCK_SIZE);
	void *key = calloc(1, BLOCK_SIZE);


	uint8_t counter = determineCounter(data, size);

	// Find all frame headers in block
	// Use headers to determine counter
	// Use counter to determine scramble pattern
	// Use headers to determine key

	size_t firstFrameHeader = findNextFrameHeader(data, size, 0);
	size_t secondFrameHeader = findNextFrameHeader(data, size, firstFrameHeader+FRAME_SIZE);

	printf("Found first frame at %zu\n", firstFrameHeader);
	printf("Found second frame at %zu\n", secondFrameHeader);

	return EXIT_SUCCESS;
}




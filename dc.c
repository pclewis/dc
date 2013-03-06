#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#define BLOCK_SIZE  0x1E00
#define KEY_REPEAT  240
#define BITRATE     128000
#define FREQUENCY   44100
#define FRAME_SIZE  144 * BITRATE / FREQUENCY
#define LOOP_OFFSET 0xF000 // I don't actually understand this value
#define BIT(i)      (1<<(i))
#define BIT_IS_SET(v,i) ((v&BIT(i))!=0)


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

bool counterBitsMatch( uint8_t c, uint16_t d, uint16_t x, size_t start, size_t end ) {
	assert( start <= 8 );
	assert( end   <= 8 );
	assert( start < end );

	for(size_t bitNum = start; bitNum < end; ++bitNum) {
		bool cbit = BIT_IS_SET(c, bitNum);
		if(cbit != (BIT_IS_SET(d, bitNum * 2 + 0) ^ BIT_IS_SET(x, bitNum * 2 + 1)) &&
		   cbit != (BIT_IS_SET(d, bitNum * 2 + 1) ^ BIT_IS_SET(x, bitNum * 2 + 1))) {
			//printf("Counter bit doesnt match: %d (%04x) (%04x) bit %d %d\n", c, d, x, bitNum, BIT_IS_SET(c, bitNum));
			return false;
		}
	}
	return true;
}

bool counterWorks(uint8_t counter, uint8_t *data, size_t offset) {
	uint8_t c = counter + (offset/2);

	if((offset%2) == 0) {
		uint16_t d = data[offset] << 8 | data[offset+1];;
		return counterBitsMatch( c, d, 0xFFFB, 0, 8 );
	} else {
		//printf("Straddle %u %u\n", data[offset], data[offset+1]);
		return counterBitsMatch( c, data[offset], 0x00FF, 0, 4) && counterBitsMatch( c+1, data[offset+1] << 8, 0xFB00, 4, 8);
	}
}

uint8_t determineCounter(uint8_t *data, size_t size) {
	uint8_t result = 0;
	unsigned int found_count = 0;
	for(uint16_t counter = 0; counter <= 255; ++counter) {
		size_t i = 0;
		bool works = true;
		while(i < LOOP_OFFSET && i < size) {
			i = findNextFrameHeader(data, size, i);
			if(!counterWorks(counter, data, i)) {
				//printf("%d abandonded at %d\n", counter, i);
				works = false;
				break;
			}
			i += FRAME_SIZE;
		}

		if(works) {
			printf("Found possible counter: %u\n", counter);
			result = counter;
			found_count += 1;
		}
	}

	if(found_count > 1) {
		printf("Warning: multiple counters found, using %u.\n", result);
	} else if (found_count == 0) {
		die("Could not determine counter");
	}
	return result;
}

void counterBitsMagic( uint8_t c, uint16_t d, uint16_t x, size_t start, size_t end, uint8_t *key, uint8_t *keyKnown, uint8_t *scramblePattern, uint8_t *scrambleKnown ) {
	assert( start <= 8 );
	assert( end   <= 8 );
	assert( start < end );

	for(size_t bitNum = start; bitNum < end; ++bitNum) {
		bool cbit = BIT_IS_SET(c, bitNum);
		bool dbit0 = (BIT_IS_SET(d, bitNum * 2 + 0) ^ BIT_IS_SET(x, bitNum * 2 + 1));
		bool dbit1 = (BIT_IS_SET(d, bitNum * 2 + 1) ^ BIT_IS_SET(x, bitNum * 2 + 1));

		if(cbit == dbit0 && cbit != dbit1) {
		   	*scrambleKnown |= BIT(bitNum);
			*scramblePattern |= BIT(bitNum);
			*keyKnown |= BIT(bitNum);
			if(BIT_IS_SET(d, bitNum * 2 + 1) ^ BIT_IS_SET(x, bitNum * 2)) *key |= BIT(bitNum);
		} else if (cbit == dbit1 && cbit != dbit0) {
			*scrambleKnown |= BIT(bitNum);
			*keyKnown |= BIT(bitNum);
			if(BIT_IS_SET(d, bitNum * 2) ^ BIT_IS_SET(x, bitNum * 2)) *key |= BIT(bitNum);
		}
	}
}


void fillInKey( uint8_t *data, size_t offset, uint8_t counter, uint8_t *scramblePattern, uint8_t *scrambleKnown, uint8_t *key, uint8_t *keyKnown ) {
	uint8_t c = counter + (offset / 2);
	size_t offs = offset % KEY_REPEAT;

	if((offset%2) == 0) {
		uint16_t d = data[offset] << 8 | data[offset+1];
		counterBitsMagic( c, d, 0xFFFB, 0, 8, key + offs, keyKnown + offs, scramblePattern + offs, scrambleKnown + offs);
	} else {
		counterBitsMagic( c+0, data[offset+0] << 0, 0x00FF, 0, 4, key + offs, keyKnown + offs, scramblePattern + offs, scrambleKnown + offs);
		offs = (offset + 1) % KEY_REPEAT;
		counterBitsMagic( c+1, data[offset+1] << 8, 0xFB00, 4, 8, key + offs, keyKnown + offs, scramblePattern + offs, scrambleKnown + offs);
	}
}

void determineKey( uint8_t *data, size_t size, uint8_t counter, uint8_t *scramblePattern, uint8_t *scrambleKnown, uint8_t *key, uint8_t *keyKnown ) {
	size_t i = 0;
	for(i = findNextFrameHeader(data, size, 0); i < LOOP_OFFSET && i < size; i = findNextFrameHeader(data, size, i + FRAME_SIZE)) {
		fillInKey( data, i, counter, scramblePattern, scrambleKnown, key, keyKnown );
	}
}

unsigned int knownBits(uint8_t *bits) {
	unsigned int count = 0;
	for (size_t i = 0; i < KEY_REPEAT; ++i) {
		for(size_t b = 0; b < 8; ++b) {
			if(BIT_IS_SET(bits[i], b)) ++count;
		}
	}
	return count;
}

void printKnownBits(uint8_t *bits, uint8_t *known) {
	for (size_t i = 0; i < 16; ++i) {
		for(int b = 7; b >= 0; --b) {
			if(BIT_IS_SET(known[i], b)) printf("%d", BIT_IS_SET(bits[i], b)); else printf(" ");
		}
	}
	printf("\n");
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


	void *scramblePattern = calloc(1, KEY_REPEAT);
	void *scrambleKnown   = calloc(1, KEY_REPEAT);
	void *key             = calloc(1, KEY_REPEAT);
	void *keyKnown        = calloc(1, KEY_REPEAT);


	uint8_t counter = determineCounter(data, size);

	determineKey( data, size, counter, scramblePattern, scrambleKnown, key, keyKnown );

	printf("Known scramble bits: %d/%d\n", knownBits(scrambleKnown), KEY_REPEAT*8 );
	printf("Known key bits: %d/%d\n", knownBits(keyKnown), KEY_REPEAT*8 );

	printKnownBits( scramblePattern, scrambleKnown );
	printKnownBits( key, keyKnown );

	return EXIT_SUCCESS;
}




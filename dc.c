#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include <getopt.h>

#define BLOCK_SIZE  0x1E00
#define BITRATE     128000
#define FREQUENCY   44100
#define FRAME_SIZE  (144 * BITRATE / FREQUENCY)
#define LOOP_OFFSET 0xF000 // I don't actually understand this value
#define BIT(i)      (1<<(i))
#define BIT_IS_SET(v,i) ((v&BIT(i))!=0)

#define FH_B3_MASK  0xFC // frames may or may not have the padding bit (bit 2) set, and it may or may not be scrambled, so ignore last two bits
#define FH_B4_MASK  0x0F // some frame use joint stereo (bits 4,5,6,7), so ignore first 4 bits
#define FH_B34_MASK ((FH_B3_MASK << 8) | FH_B4_MASK)

#define MAX_KEY_REPEAT 240
static const size_t KEY_REPEATS[] = { 30, 40, 48, 60, 80, 120, 240, 0 };

typedef struct {
	uint8_t counter;
	size_t keySize;
	uint8_t key[MAX_KEY_REPEAT];
	uint8_t scramble[MAX_KEY_REPEAT];
} DCState;

void die(char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

size_t findNextFrameHeader(uint8_t *data, size_t size, size_t start, int dir) {
	size_t i = 0;

	for(i = start; i < size; i += dir) {
		if( data[i] == data[dir*LOOP_OFFSET+i] && data[i+1] == data[dir*LOOP_OFFSET+i+1]) {
			uint8_t b1 = data[i], b2 = data[i+1], b3 = data[i+2] & FH_B3_MASK, b4 = data[i+3] & FH_B4_MASK;
			bool found = true;
			for(size_t j = i % LOOP_OFFSET; j < (size-4); j += LOOP_OFFSET) {
				if(data[j] != b1 || data[j+1] != b2 || (data[j+2] & FH_B3_MASK) != b3 || (data[j+3] & FH_B4_MASK) != b4) {
					//if (i == 0) printf("No frame at 0 (%u): (%02x, %02x, %02x, %02x) (%02x, %02x, %02x, %02x)\n", j, data[j], data[j+1], data[j+2] & FH_B3_MASK, data[j+3] & FH_B4_MASK, b1, b2, b3, b4);
					found = false;
					break;
				}
			}
			if(found) break;
		}
	}

	if( (start != 0) && ((i - start) % FRAME_SIZE) > 1 ) printf("Suspicious frame offset: %zu -> %zu\n", start, i);
	//printf("Found frame header at %u\n", i);
	return i;
}

void swapBytes(uint8_t *data, size_t size) {
	for(size_t i = 0; i < size-1; i += 2) {
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
			i = findNextFrameHeader(data, size, i, 1);
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

bool deriveKey( uint8_t *data, size_t offset, uint16_t plainBytes, uint16_t mask, DCState *state, DCState *known ) {
	uint16_t cipherBytes     = (data[offset] << 8) | data[offset+1];
	uint8_t  counter         = state->counter + (offset / 2);
	size_t   keyOffset       = (offset / 2) % state->keySize;
	uint8_t *scrambleKnown   = known->scramble + keyOffset;
	uint8_t *keyKnown        = known->key      + keyOffset;
	uint8_t *key             = state->key      + keyOffset;
	uint8_t *scramblePattern = state->scramble + keyOffset;

#define COLLISION(type, n) { /* printf(type " collision " n "  @ bit %zu (counter=%u offs=%zu cb=%04x pb=%04x m=%04x ks=%zu ko=%zu)\n", bitNum, counter, offset, cipherBytes, plainBytes, mask, state->keySize, keyOffset); */ return false; }
	assert( (offset % 2) == 0 );

	for(size_t bitNum = 0; bitNum < 8; ++bitNum) {
		if(!BIT_IS_SET(mask, bitNum * 2) || !BIT_IS_SET(mask, bitNum * 2 + 1)) continue;

		bool counterBit   = BIT_IS_SET(counter, bitNum);
		bool oppositeCounterBit = BIT_IS_SET(counter, 7 - bitNum);
		bool ptKeyBit     = BIT_IS_SET(plainBytes, bitNum * 2);
		bool ptCounterBit = BIT_IS_SET(plainBytes, bitNum * 2 + 1);
		bool xbit0        = BIT_IS_SET(cipherBytes, bitNum * 2 + 0) ^ ptCounterBit;
		bool xbit1        = BIT_IS_SET(cipherBytes, bitNum * 2 + 1) ^ ptCounterBit;

		if(xbit0 == xbit1) {
			// Don't know if it's scrambled, but the key is the same either way
			assert( BIT_IS_SET(cipherBytes, bitNum*2) == BIT_IS_SET(cipherBytes, bitNum*2+1));
			bool bit = BIT_IS_SET(cipherBytes, bitNum * 2) ^ ptKeyBit ^ oppositeCounterBit;
			if(BIT_IS_SET(*keyKnown, bitNum) && BIT_IS_SET(*key, bitNum)!=bit) COLLISION("key", "0");
			/*
			if(bit) *key |= BIT(bitNum);
			*keyKnown |= BIT(bitNum);
			*/
		} else if(counterBit == xbit0) {
			if( BIT_IS_SET(*scrambleKnown, bitNum) && !BIT_IS_SET(*scramblePattern, bitNum) ) COLLISION( "scramble", "A" );
		   	*scrambleKnown   |= BIT(bitNum);
			*scramblePattern |= BIT(bitNum);
			bool bit = BIT_IS_SET(cipherBytes, bitNum * 2 + 1) ^ ptKeyBit ^ oppositeCounterBit;
			if(BIT_IS_SET(*keyKnown, bitNum) && BIT_IS_SET(*key, bitNum)!=bit) COLLISION("key", "A");
			if(bit) *key |= BIT(bitNum);
			*keyKnown |= BIT(bitNum);
		} else {
			if( BIT_IS_SET(*scrambleKnown, bitNum) && BIT_IS_SET(*scramblePattern, bitNum) ) COLLISION("scramble", "B");
			*scrambleKnown |= BIT(bitNum);

			bool bit = BIT_IS_SET(cipherBytes, bitNum * 2) ^ ptKeyBit ^ oppositeCounterBit;
			if(BIT_IS_SET(*keyKnown, bitNum) && BIT_IS_SET(*key, bitNum)!=bit) COLLISION("key", "B");
			if(bit) *key |= BIT(bitNum);
			*keyKnown |= BIT(bitNum);
		}
	}
	return true;
}

bool determineKey( uint8_t *data, size_t size, DCState *state, DCState *known ) {
	size_t i = 0;
	for(i = findNextFrameHeader(data, size, 0, 1); i < (LOOP_OFFSET-4) && i < (size-4); i = findNextFrameHeader(data, size, i + FRAME_SIZE, 1)) {
		if((i%2) == 0) {
			if (!deriveKey( data, i+0, 0xFFFB, 0xFFFF,              state, known)) return false;
			if (!deriveKey( data, i+2, 0x9000, FH_B34_MASK,         state, known)) return false;
		} else {
			if (!deriveKey( data, i-1, 0x00FF, 0x00FF,              state, known)) return false;
			if (!deriveKey( data, i+1, 0xFB90, 0xFF00 | FH_B3_MASK, state, known)) return false;
			if (!deriveKey( data, i+3, 0x0000, FH_B4_MASK << 8,     state, known)) return false;
		}
	}
	return true;
}

unsigned int knownBits(uint8_t *bits) {
	unsigned int count = 0;
	for (size_t i = 0; i < MAX_KEY_REPEAT; ++i) {
		for(size_t b = 0; b < 8; ++b) {
			if(BIT_IS_SET(bits[i], b)) ++count;
		}
	}
	return count;
}

void printKnownBits(uint8_t *bits, uint8_t *known) {
	for (size_t i = 0; i < 32; ++i) {
		for(int b = 7; b >= 0; --b) {
			if(BIT_IS_SET(known[i], b)) printf("%d", BIT_IS_SET(bits[i], b)); else printf(" ");
		}
	}
	printf("\n");
}

static inline uint8_t reverseBits(uint8_t b) {// hax
	return ((b * 0x0802LU & 0x22110LU) | (b * 0x8020LU & 0x88440LU)) * 0x10101LU >> 16; 
}

/* note: data should already be byte swapped */
void *decryptData( uint8_t *data, size_t size, DCState *state ) { 
	uint8_t *result = malloc( size );
	uint8_t counter = state->counter;
	for(size_t i = 0; i < size; i += 2) {
		uint16_t iv = data[i] << 8 | data[i+1];
		uint16_t ov = 0;

		for(size_t b = 0; b < 8; ++b) {
			bool b1 = BIT_IS_SET( iv, b*2 ), b2 = BIT_IS_SET( iv, b*2+1 );
			if(BIT_IS_SET(state->scramble[(i/2) % state->keySize], b)) {
				bool t = b1; b1 = b2; b2 = t;
			}

			if( b1 ^ BIT_IS_SET(counter, 7-b) ^ BIT_IS_SET(state->key[(i/2) % state->keySize], b)) ov |= BIT(b*2);
			if( b2 ^ BIT_IS_SET(counter, b) ) ov |= BIT(b*2+1);
		}

		result[i+1] = ov & 0xFF;
		result[i] = ov >> 8 & 0xFF;
		counter += 1;
	}

	return result;
}


void usage(char *pname) {
	printf("Usage: %s [-k inkey] [-K outkey] [-s inscramble] [-S outscramble] [-c counter] [-O outstate] <infile> [outfile]\n", pname);
	printf("\n");
}

FILE *confirmOpen(const char *fn, const char *mode) {
	FILE *fp = fopen(fn, mode);
	if(!fp) perror(fn);
	return fp;
}

void writeFile(const char *desc, FILE *fp, void *data, size_t size) {
	size_t wroteBytes = fwrite(data, 1, size, fp);
	printf("Wrote %s: %zu/%zu bytes\n", desc, wroteBytes, size);
}

long fileSize(FILE *fp) {
	long start = ftell(fp);
	fseek(fp, 0, SEEK_END);
	long result = ftell(fp);
	fseek(fp, start, SEEK_SET);
	return result;
}

int main(int argc, char *argv[]) {
	int status        = EXIT_FAILURE;

	FILE *inKey       = NULL;
	FILE *outKey      = NULL;
	FILE *inScramble  = NULL;
	FILE *outScramble = NULL;
	FILE *outState    = NULL;
	FILE *inFile      = NULL;
	FILE *outFile     = NULL;
	uint8_t counter   = 0;
	bool counterSet   = false;
	void *data        = NULL;

	DCState *state = calloc(1, sizeof(DCState));
	DCState *known = calloc(1, sizeof(DCState));

	int c;
	while((c = getopt(argc, argv, "hk:K:s:S:c:O:")) != -1) {
		switch(c) {
			case 'k': inKey       = confirmOpen(optarg, "rb"); break;
			case 'K': outKey      = confirmOpen(optarg, "wb"); break;
			case 's': inScramble  = confirmOpen(optarg, "rb"); break;
			case 'S': outScramble = confirmOpen(optarg, "wb"); break;
			case 'O': outState    = confirmOpen(optarg, "wb"); break;
			case 'c': 
				counter = atoi(optarg);
				counterSet = true;
				break;
			case 'h':
			case '?':
				usage(argv[0]);
				goto done;
		}
	}
	if(optind < argc) inFile  = confirmOpen(argv[optind++], "rb");
	if(optind < argc) outFile = confirmOpen(argv[optind++], "wb");
	if(optind < argc || inFile == NULL) {
		usage(argv[0]);
		goto done;
	}

	fseek(inFile, 0, SEEK_END);
	size_t size = ftell(inFile);
	fseek(inFile, 0, SEEK_SET);

	data = malloc( size );

	size_t readBytes = fread(data, 1, size, inFile);
	if(readBytes < size) die("Read %zu of %zu bytes", readBytes, size);
	fclose(inFile);
	inFile = NULL;

	printf("Swapping bytes\n");
	swapBytes(data, size);

	if(inKey) {
		state->keySize = fileSize(inKey);
		known->keySize = state->keySize;
		fread(&state->key, 1, state->keySize, inKey);
		memset(&known->key, 0xFF, MAX_KEY_REPEAT);
		fclose(inKey);
		inKey = NULL;
	}

	if(inScramble) {
		long scrambleSize = fileSize(inScramble);
		if(state->keySize && state->keySize != scrambleSize) {
			printf("Key has length %zu but scramble has length %ld", state->keySize, scrambleSize);
			goto done;
		} else {
			state->keySize = scrambleSize;
			known->keySize = state->keySize;
		}
		fread(&state->scramble, 1, scrambleSize, inScramble);
		memset(&known->scramble, 0xFF, MAX_KEY_REPEAT);
		fclose(inScramble);
		inScramble = NULL;
	}

	if(!counterSet) counter = determineCounter(data, size);
	state->counter = counter;

	if(state->keySize == 0) {
		size_t keySize = 0;

		for(size_t kri = 0; (keySize = KEY_REPEATS[kri]) != 0; ++kri) {
			printf("Trying key size %zu\n", keySize);
			memset( state, 0, sizeof(DCState) );
			memset( known, 0, sizeof(DCState) );
			state->counter = known->counter = counter;
			state->keySize = known->keySize = keySize;
			if(determineKey( data, size, state, known ))
				break;
		}

		if(keySize == 0) {
			printf("Couldn't find key size\n");
			goto done;
		}
	}

	if(knownBits(known->scramble) < known->keySize*8) {
		printf("Not enough scramble bits, trying to find 0x00 frames\n");
		DCState *orig_state = malloc(sizeof(DCState));
		DCState *orig_known = malloc(sizeof(DCState));

		/* Last byte in file is always 0x00  */
		if(!deriveKey( data, size - 2, 0x0000, 0x00FF, state, known )) printf("Last byte not 0?\n");

		/* First byte after first frame header is always 0x00  */
		size_t ffh = findNextFrameHeader(data, size, 0, 1);
		if(ffh%2==0) {
			if(!deriveKey( data, ffh+4, 0x0000, 0xFF00, state, known )) printf("no 0 after first frame header?\n");
		} else {
			if(!deriveKey( data, ffh+3, 0x0000, 0x00FF, state, known )) printf("no 0 after first frame header?\n");;
		}

		int zf = 0;
		for(size_t bi = findNextFrameHeader(data, size, 0, 1); bi < size && bi < LOOP_OFFSET; bi = findNextFrameHeader(data, size, bi + FRAME_SIZE, 1)) {
			for (size_t fi = bi; fi < size; fi += LOOP_OFFSET) { 
				int adj = (fi%2==0) ? 1 : 0;
				bool success = true;
				memcpy( orig_state, state, sizeof(DCState) );
				memcpy( orig_known, known, sizeof(DCState) );
				for(size_t i = fi + 0x21 + adj; i < fi + FRAME_SIZE - 1; i += 2) {
					if( !deriveKey( data, i, 0x0000, 0xFFFF, state, known ) ) {
						success = false;
						break;
					}
				}
				if(!success) {
					memcpy( state, orig_state, sizeof(DCState) );
					memcpy( known, orig_known, sizeof(DCState) );
				} else {
					zf++;
				}
			}
			if(knownBits(known->key) >= known->keySize*8) break; 
		}

		printf("Found %d 0x00 frames\n", zf);

		if(knownBits(known->scramble) < known->keySize*8) {
			printf("Still not enough scramble bits, trying to find runs of 0xFFFFFFFFFFFF\n");
			for(size_t bi = findNextFrameHeader(data, size, 0, 1); bi < size && bi < LOOP_OFFSET; bi = findNextFrameHeader(data, size, bi + FRAME_SIZE, 1)) {
				for (size_t fi = bi; fi < size; fi += LOOP_OFFSET) { 
					int adj = (fi%2==0) ? 0 : 1;

					for(size_t si = fi + adj; si < fi + FRAME_SIZE - 6; si += 2) {
						memcpy( orig_state, state, sizeof(DCState) );
						memcpy( orig_known, known, sizeof(DCState) );

						if(!deriveKey(data, si, 0xFFFF, 0xFFFF, state, known) ||
							!deriveKey(data, si+2, 0xFFFF, 0xFFFF, state, known) ||
							!deriveKey(data, si+4, 0xFFFF, 0xFFFF, state, known)) {
							memcpy( state, orig_state, sizeof(DCState) );
							memcpy( known, orig_known, sizeof(DCState) );
						} else {
							si += 4;
						}
					}
				}
				if(knownBits(known->key) >= known->keySize*8) break; 
			}
		}

		if(knownBits(known->scramble) < known->keySize*8) {
			printf("Still not enough scramble bits, trying to find runs of 0x000000000000\n");
			for(size_t bi = findNextFrameHeader(data, size, 0, 1); bi < size && bi < LOOP_OFFSET; bi = findNextFrameHeader(data, size, bi + FRAME_SIZE, 1)) {
				for (size_t fi = bi; fi < size; fi += LOOP_OFFSET) { 
					int adj = (fi%2==0) ? 0 : 1;

					for(size_t si = fi + adj; si < fi + FRAME_SIZE - 6; si += 2) {
						memcpy( orig_state, state, sizeof(DCState) );
						memcpy( orig_known, known, sizeof(DCState) );

						if(!deriveKey(data, si, 0x0000, 0xFFFF, state, known) ||
							!deriveKey(data, si+2, 0x0000, 0xFFFF, state, known) ||
							!deriveKey(data, si+4, 0x0000, 0xFFFF, state, known)) {
							memcpy( state, orig_state, sizeof(DCState) );
							memcpy( known, orig_known, sizeof(DCState) );
						} else {
							si += 4;
						}
					}
				}
				if(knownBits(known->key) >= known->keySize*8) break; 
			}
		}

	}

	printf("Known scramble bits: %d/%zu\n", knownBits(known->scramble), known->keySize*8 );
	printf("Known key bits: %d/%zu\n", knownBits(known->key), known->keySize*8 );

	printKnownBits( state->scramble, known->scramble );
	printKnownBits( state->key, known->key );

	if(outKey      != NULL) writeFile( "key",      outKey,      &state->key,      state->keySize  );
	if(outScramble != NULL) writeFile( "scramble", outScramble, &state->scramble, state->keySize  );
	if(outState    != NULL) writeFile( "state",    outState,    state,           sizeof(DCState) );

	if(outFile!=NULL) {
		void * out = decryptData(data, size, state); 
		writeFile("decrypted data", outFile, out, size);
		free(out);
	}

	status = EXIT_SUCCESS;

done:
	if(data) free(data);
	if(state) free(state);
	if(known) free(known);

	if(inFile) fclose(inFile);
	if(outFile) fclose(outFile);
	if(inKey) fclose(inKey);
	if(outKey) fclose(outKey);
	if(inScramble) fclose(inScramble);
	if(outScramble) fclose(outScramble);
	if(outState) fclose(outState);
	return status;
}




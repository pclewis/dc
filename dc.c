#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <getopt.h>
#include "util.h"

#define BLOCK_SIZE  0xF00 // lcm(MAX_KEY_REPEAT, 2**COUNTER_BITS=256)

#define FH_B3_MASK  0xFC // frames may or may not have the padding bit (bit 2) set, and it may or may not be scrambled, so ignore last two bits
#define FH_B4_MASK  0x03 // some frame use joint stereo (bits 4,5,6,7), or orig/copyright (2,3) so ignore first 6 bits
#define FH_B34_MASK ((FH_B3_MASK << 8) | FH_B4_MASK)
#define FH_MASK     (0xFFFF0000 | FH_B34_MASK)

#define MAX_KEY_REPEAT 240
static const size_t KEY_REPEATS[] = { 30, 40, 48, 60, 80, 120, 240, 0 };

typedef struct {
	uint8_t key[MAX_KEY_REPEAT];
	uint8_t scramble[MAX_KEY_REPEAT];
} DCState;

typedef struct {
	uint8_t counter;
	size_t keySize;
	DCState state;
} DCSaveState;

typedef struct {
	uint8_t counter;
	size_t keySize;
	unsigned int bitRate;
	unsigned int frequency;
	size_t frameSize;
	uint32_t frameHeader;

	uint8_t *data;
	size_t size;
	size_t *frameHeaders;
	size_t n_frameHeaders;

	DCState state;
	DCState known;
} DCInfo;

static DCInfo *dcinfo_new() {
	DCInfo *info = calloc_safe(1, sizeof(DCInfo));
	info->bitRate = 128000;
	info->frequency = 44100;
	return info;
}

static void dcinfo_calculateFrameInfo(DCInfo *info) {
	uint8_t bbits = 0, fbits = 0;
	switch(info->bitRate) {
		case 32000:  bbits =  1; break;
		case 40000:  bbits =  2; break;
		case 48000:  bbits =  3; break;
		case 56000:  bbits =  4; break;
		case 64000:  bbits =  5; break;
		case 80000:  bbits =  6; break;
		case 96000:  bbits =  7; break;
		case 112000: bbits =  8; break;
		case 128000: bbits =  9; break;
		case 160000: bbits = 10; break;
		case 192000: bbits = 11; break;
		case 224000: bbits = 12; break;
		case 256000: bbits = 13; break;
		case 320000: bbits = 14; break;
		default: die("Unsupported bitrate: %u\n", info->bitRate);
	}
	switch(info->frequency) {
		case 44100: fbits = 0; break;
		case 48000: fbits = 1; break;
		case 32000: fbits = 2; break;
		default: die("Invalid frequency: %u\n", info->frequency);
	}
	info->frameSize = 144 * info->bitRate / info->frequency;
	info->frameHeader = 0xFFFB0000 | (bbits << 12) | (fbits << 10);	
}

static void dcinfo_free(DCInfo *info) {
	if(info->data) free(info->data);
	if(info->frameHeaders) free(info->frameHeaders);
	free(info);
}

// Treat any offset that would be inside another another frame as equal 
static size_t _frame_size;
static int compareFrameHeaderPointer(const void *v1, const void *v2) {
	size_t s1 = *(size_t*)v1, s2 = *(size_t*)v2;
	size_t diff = (s1 < s2) ? s2 - s1 : s1 - s2; // diff = abs(s1 - s2)
	if(diff < _frame_size) return 0;
	return (s1 < s2) ? -1 : 1;
}

static inline size_t nextOffset(size_t i, size_t *result, size_t n_results, size_t frameSize, /* IN/OUT */ size_t *maxOffset) {
	// If this offset collides with another frame we already found, jump to the end of that frame.
	// Note this also handles the case where we just added a result in the previous iteration.
	size_t *match = bsearch(&i, result, n_results, sizeof(*result), compareFrameHeaderPointer);
	if(match) {
		*maxOffset = 1;
		do {
			i = *match + frameSize;
		} while ( (match = bsearch(&i, result, n_results, sizeof(*result), compareFrameHeaderPointer)) != NULL );
		return i;
	}

	if(*maxOffset < frameSize)
		*maxOffset += 1; // since we dont know if this frame was padded, next frame could be 1 byte further
	if(*maxOffset >= frameSize) {
		printf("MaxOffset critical: %zu offset=%zu\n", *maxOffset, i);
	}
	printf("Couldn't find frame expected at offset %zu\n", i);
	return i + frameSize;
}

static size_t findMatches(uint8_t *data, size_t size, size_t offset, size_t *result, size_t n_results) {
	uint32_t value = ((data[offset] << 24) | (data[offset+1] << 16) | (data[offset+2] << 8) | data[offset+3]) & FH_MASK;
	//printf("%08x %02x %02x %02x %02x\n", value, data[offset], data[offset+1], data[offset+2], data[offset+3]);
	size_t n_found = 0;

	/* start at beginning so we can short circuit on backwards matches inside of other frames */
	for(size_t i = (offset % BLOCK_SIZE); i <= (size - 4); i += BLOCK_SIZE) {
		uint32_t compare = ((data[i] << 24) | (data[i+1] << 16) | (data[i+2] << 8) | data[i+3]) & FH_MASK;
		//if(offset == 417 || offset == 418) printf("%zu %08x %08x\n", offset, value, compare);
		if(value == compare) {
			// Don't match anything we've already added or that contains part of what we've already added.
			// Only searching results that we didn't just add.
			if(bsearch(&i, result, n_results, sizeof(*result), compareFrameHeaderPointer) != NULL) {
				//printf("Short circuit: match inside other frame\n");
				return 0;
			}

			result[n_results + n_found] = i;
			n_found += 1;
		}
	}

	return n_found;
}

/**
 * Search for frame headers in an encrypted buffer.
 * 
 * @param  data          Buffer to search
 * @param  size          Size of buffer
 * @param  frameSize     Expected size of unpadded frame
 * @param  out_n_headers Variable to store total number of found headers in.
 * @return               New array of pointers into data in ascending order. Caller must free.
 */
static size_t *findFrameHeaders(uint8_t *data, size_t size, size_t frameSize, size_t *out_n_headers) {
	size_t n_results = 0, n_allocated = size/frameSize;
	size_t *result = calloc(n_allocated, sizeof(*result));
	unsigned int requiredMatches = 3;
	size_t minMatchSpace = (BLOCK_SIZE * requiredMatches) + 3; // from any given offset, we need enough blocks to find matches in, and 3 more bytes for the rest of the frame header
	size_t maxOffset = 16; // max bytes we'll search before jumping ahead by a whole frame.

	_frame_size = frameSize;

	if( minMatchSpace > size ) die("Not enough data to find frame headers. Size=%zu Max possible matches: %zu Min size for match: %zu", size, size / BLOCK_SIZE, minMatchSpace );

	for(size_t i = 0; i < size - minMatchSpace; i=nextOffset(i, result, n_results, frameSize, &maxOffset)) {
		size_t mostFound = 0, mostFoundOffset = 0, mfc = 0;

		for(size_t curOffset = 0; curOffset <= maxOffset; ++curOffset) {
			size_t found = findMatches(data, size, i+curOffset, result, n_results);
			if(found == mostFound) {
				++mfc;
			} else if(found > mostFound) {
				mfc = 1;
				mostFound = found;
				mostFoundOffset = curOffset;
				//if(found >= requiredMatches) break;
			}
		}

		//printf("Offset=%zu, mostFound=%zu, mfo=%zu\n", i, mostFound, mostFoundOffset);

		if(mfc > 1) {
			printf("Don't know which offset to pick at %zu\n", i);
			continue;
		}

		if(mostFound >= requiredMatches) {
			if(mostFoundOffset != maxOffset) { /* rerun if it's not the last one we ran */
				findMatches(data, size, i+mostFoundOffset, result, n_results);
			}

			n_results += mostFound;

			// only need to sort once we're done adding
			qsort(result, n_results, sizeof(*result), compareFrameHeaderPointer);
		}
	}

	*out_n_headers = n_results;
	return result;
}

static void swapBytes(uint8_t *data, size_t size) {
	for(size_t i = 0; i < size-1; i += 2) {
		uint8_t tmp = data[i];
		data[i] = data[i+1];
		data[i+1] = tmp;
	}
}

static bool deriveKey( const uint8_t *data, size_t offset, uint16_t plainBytes, uint16_t mask, uint8_t initCounter, size_t keySize, DCState *state, DCState *known ) {
	uint16_t cipherBytes     = (data[offset] << 8) | data[offset+1];
	uint8_t  counter         = initCounter + (offset / 2);
	size_t   keyOffset       = (offset / 2) % keySize;
	uint8_t *scrambleKnown   = known->scramble + keyOffset;
	uint8_t *keyKnown        = known->key      + keyOffset;
	uint8_t *key             = state->key      + keyOffset;
	uint8_t *scramblePattern = state->scramble + keyOffset;

	uint8_t orig_sk = *scrambleKnown, orig_kk = *keyKnown, orig_k = *key, orig_sp = *scramblePattern;

#define COLLISION(type, n) { /* printf(type " collision " n "  @ bit %zu (counter=%u offs=%zu cb=%04x pb=%04x m=%04x ks=%zu ko=%zu)\n", bitNum, counter, offset, cipherBytes, plainBytes, mask, keySize, keyOffset);*/ \
	*scrambleKnown = orig_sk; *keyKnown = orig_kk; *key = orig_k; *scramblePattern = orig_sp; \
	return false; }
	assert( (offset % 2) == 0 );

	for(size_t bitNum = 0; bitNum < 8; ++bitNum) {
		if(!BIT_IS_SET(mask, bitNum * 2) || !BIT_IS_SET(mask, bitNum * 2 + 1)) continue;

		bool counterBit   = BIT_IS_SET(counter, bitNum);
		bool oppositeCounterBit = BIT_IS_SET(counter, 7 - bitNum);
		bool ptKeyBit     = BIT_IS_SET(plainBytes, bitNum * 2);
		bool ptCounterBit = BIT_IS_SET(plainBytes, bitNum * 2 + 1);
		bool xbit0        = BIT_IS_SET(cipherBytes, bitNum * 2 + 0) ^ ptCounterBit;
		bool xbit1        = BIT_IS_SET(cipherBytes, bitNum * 2 + 1) ^ ptCounterBit;

		if(counterBit != xbit0 && counterBit != xbit1) COLLISION("counter bit don't fit", "q");

		if(xbit0 == xbit1) {
			// Don't know if it's scrambled, but the key is the same either way
			assert( BIT_IS_SET(cipherBytes, bitNum*2) == BIT_IS_SET(cipherBytes, bitNum*2+1));
			bool bit = BIT_IS_SET(cipherBytes, bitNum * 2) ^ ptKeyBit ^ oppositeCounterBit;
			if(BIT_IS_SET(*keyKnown, bitNum) && BIT_IS_SET(*key, bitNum)!=bit) COLLISION("key", "0");
			if(bit) *key |= BIT(bitNum);
			*keyKnown |= BIT(bitNum);
		} else if(counterBit == xbit0) {
			bool bit = BIT_IS_SET(cipherBytes, bitNum * 2 + 1) ^ ptKeyBit ^ oppositeCounterBit;
			if(BIT_IS_SET(*scrambleKnown, bitNum) && !BIT_IS_SET(*scramblePattern, bitNum)) COLLISION( "scramble", "A" );
			if(BIT_IS_SET(*keyKnown, bitNum) && BIT_IS_SET(*key, bitNum)!=bit) COLLISION("key", "A");
		   	*scrambleKnown   |= BIT(bitNum);
			*scramblePattern |= BIT(bitNum);
			if(bit) *key |= BIT(bitNum);
			*keyKnown |= BIT(bitNum);
		} else if(counterBit == xbit1) {
			bool bit = BIT_IS_SET(cipherBytes, bitNum * 2) ^ ptKeyBit ^ oppositeCounterBit;
			if(BIT_IS_SET(*scrambleKnown, bitNum) && BIT_IS_SET(*scramblePattern, bitNum)) COLLISION("scramble", "B");
			if(BIT_IS_SET(*keyKnown, bitNum) && BIT_IS_SET(*key, bitNum)!=bit) COLLISION("key", "B");
			*scrambleKnown |= BIT(bitNum);
			if(bit) *key |= BIT(bitNum);
			*keyKnown |= BIT(bitNum);
		}
	}
	return true;
}

static bool deriveKey32( const uint8_t *data, const size_t offset, const uint32_t plainBytes, const uint32_t mask, const uint8_t counter, const size_t keySize, DCState *state, DCState *known ) {
	if((offset%2) == 0) {
		if (!deriveKey( data, offset+0, plainBytes >> 16,          mask >> 16,            counter, keySize, state, known)) return false;
		if (!deriveKey( data, offset+2, plainBytes & 0xFFFF,       mask & 0xFFFF,         counter, keySize, state, known)) return false;
	} else {
		if (!deriveKey( data, offset-1, plainBytes >> 24,          mask >> 24,            counter, keySize, state, known)) return false;
		if (!deriveKey( data, offset+1, plainBytes >> 8,           mask >> 8,             counter, keySize, state, known)) return false;
		if (!deriveKey( data, offset+3, (plainBytes & 0xFF) << 8, (mask & 0xFF) << 8,     counter, keySize, state, known)) return false;
	}
	return true;
}

static size_t nextKeySize(size_t keySize) {
	for(size_t i = 0; KEY_REPEATS[i] != 0; ++i)
		if(KEY_REPEATS[i] == keySize) return KEY_REPEATS[i+1];
	return 0;
}

static bool prepareCounterAndKey( DCInfo *info, const bool counterKnown, const bool keySizeKnown ) {
	if(!counterKnown) info->counter = 0;
	if(!keySizeKnown) info->keySize = KEY_REPEATS[0];

	DCState origState, origKnown;
	memcpy( &origState, &info->state, sizeof(info->state) );
	memcpy( &origKnown, &info->known, sizeof(info->known) );

	struct {
		unsigned int count;
		uint8_t counter;
		size_t keySize;
	} minMisses = {info->n_frameHeaders,0,0};

	while(true) {
		//printf("Trying keySize %zu counter %u\n", info->keySize, info->counter);

		unsigned int misses = 0;

		for(size_t i = 0; i < info->n_frameHeaders; ++i) {
			if( !deriveKey32( info->data, info->frameHeaders[i], info->frameHeader, FH_MASK, info->counter, info->keySize, &info->state, &info->known ) ) {
				++misses;
			}
		}

		if(misses == 0) return true;
		if(misses < minMisses.count) {
			minMisses.count   = misses;
			minMisses.counter = info->counter;
			minMisses.keySize = info->keySize;
		}
		//printf("ks %zu c %u misses=%d\n", info->keySize, info->counter, misses);

		if(counterKnown || info->counter == 255) {
			if(keySizeKnown) break;
			if(!counterKnown) info->counter = 0;
			info->keySize = nextKeySize(info->keySize);
			if(info->keySize == 0) break;
		} else {
			info->counter += 1;
		}

		memcpy( &info->state, &origState, sizeof(info->state) );
		memcpy( &info->known, &origKnown, sizeof(info->known) );
	}

	if(minMisses.count < info->n_frameHeaders/6) { // arbitrary ratio, usually invalid counters have almost all misses, correct counter but wrong key size has as few as 1/2.
		printf("Guessing counter=%u keySize=%zu, removing %u conflicting frames\n", minMisses.counter, minMisses.keySize, minMisses.count);

		info->counter = minMisses.counter;
		info->keySize = minMisses.keySize;

		// Set all conflicting frames to SIZE_MAX, so we can just sort them to the end and chop them off.
		for(size_t i = 0; i < info->n_frameHeaders; ++i) {
			if( !deriveKey32( info->data, info->frameHeaders[i], info->frameHeader, FH_MASK, info->counter, info->keySize, &info->state, &info->known ) ) {
				info->frameHeaders[i] = SIZE_MAX;
			}
		}
		qsort(info->frameHeaders, info->n_frameHeaders, sizeof(*info->frameHeaders), compareFrameHeaderPointer);
		info->n_frameHeaders -= minMisses.count;
		return true;
	} else {
		printf("Too many misses to guess counter: %u\n", minMisses.count);
	}

	return false;
}

static unsigned int knownBits(uint8_t *bits) {
	unsigned int count = 0;
	for (size_t i = 0; i < MAX_KEY_REPEAT; ++i) {
		for(size_t b = 0; b < 8; ++b) {
			if(BIT_IS_SET(bits[i], b)) ++count;
		}
	}
	return count;
}

/**
 * Fill in frame headers based on gaps between other headers.
 *
 * Ex: If unpadded frame size is 417 and there are frame headers at 20062 and 21734, there are 418*4 bytes in between so no unpadded frames are possible.
 *     Thus there must also be frame headers at 20480, 20989, and 21316.
 */
static void findImpliedFrameHeaders(DCInfo *info) {
	size_t pfs = info->frameSize + 1;
	size_t n_added = 0;

	for(size_t i = 0; i < info->n_frameHeaders - 1; ++i) {
		size_t from = info->frameHeaders[i];
		size_t to   = info->frameHeaders[i+1];
		size_t diff = to - from;

		if(diff > pfs && (diff % pfs) == 0) {
			for(size_t p = from + pfs; p < to; p += pfs) {
				info->frameHeaders[info->n_frameHeaders + n_added] = p;
				n_added += 1;
			}
		}
	}
	printf("Added %zu implied frame headers\n", n_added);
	info->n_frameHeaders += n_added;
	qsort(info->frameHeaders, info->n_frameHeaders, sizeof(*info->frameHeaders), compareFrameHeaderPointer);
}

static void printKnownBits(uint8_t *bits, uint8_t *known) {
	for (size_t i = 0; i < 32; ++i) {
		for(int b = 7; b >= 0; --b) {
			if(BIT_IS_SET(known[i], b)) printf("%d", BIT_IS_SET(bits[i], b)); else printf(" ");
		}
	}
	printf("\n");
}

/* note: data should already be byte swapped */
static void *decryptData( uint8_t *data, size_t size, uint8_t counter, size_t keySize, DCState *state ) { 
	uint8_t *result = malloc( size );
	for(size_t i = 0; i < size; i += 2) {
		uint16_t iv = data[i] << 8 | data[i+1];
		uint16_t ov = 0;

		for(size_t b = 0; b < 8; ++b) {
			bool b1 = BIT_IS_SET( iv, b*2 ), b2 = BIT_IS_SET( iv, b*2+1 );
			if(BIT_IS_SET(state->scramble[(i/2) % keySize], b)) {
				bool t = b1; b1 = b2; b2 = t;
			}

			if( b1 ^ BIT_IS_SET(counter, 7-b) ^ BIT_IS_SET(state->key[(i/2) % keySize], b)) ov |= BIT(b*2);
			if( b2 ^ BIT_IS_SET(counter, b) ) ov |= BIT(b*2+1);
		}

		result[i+1] = ov & 0xFF;
		result[i] = ov >> 8 & 0xFF;
		counter += 1;
	}

	return result;
}

static void *encryptData( uint8_t *data, size_t size, uint8_t counter, size_t keySize, DCState *state ) { 
	uint8_t *result = malloc( size );
	printf("Counter %u\n", counter);
	for(size_t i = 0; i < size; i += 2) {
		uint16_t iv = data[i] << 8 | data[i+1];
		uint16_t ov = 0;

		for(size_t b = 0; b < 8; ++b) {
			bool b1 = BIT_IS_SET( iv, b*2 ), b2 = BIT_IS_SET( iv, b*2+1 );
			bool ob1 = b1 ^ BIT_IS_SET(counter, 7-b) ^ BIT_IS_SET(state->key[(i/2) % keySize], b);
			bool ob2 = b2 ^ BIT_IS_SET(counter, b);
			if(BIT_IS_SET(state->scramble[(i/2) % keySize], b)) {
				bool t = ob1; ob1 = ob2; ob2 = t;
			}
			if(ob1) ov |= BIT(b*2);
			if(ob2) ov |= BIT(b*2+1);
		}

		// swap
		result[i] = ov & 0xFF;
		result[i+1] = ov >> 8 & 0xFF;
		counter += 1;
	}

	return result;
}

static void writeFile( const char *desc, FILE *fp, void *data, size_t size ) {
	size_t bytes = fwrite_safe(fp, data, size);
	printf("Wrote %s: %zu bytes\n", desc, bytes);
}

static void readState( DCInfo *info, const char *fn ) {
	DCSaveState saveState;
	fopen_and_read( &saveState, sizeof(saveState), fn, "rb" );
	info->keySize = saveState.keySize;
	info->counter = saveState.counter;
	memcpy( &info->state.key, &saveState.state.key, MAX_KEY_REPEAT );
	memcpy( &info->state.scramble, &saveState.state.scramble, MAX_KEY_REPEAT );
	memset( &info->known.key, 0xFF, MAX_KEY_REPEAT );
	memset( &info->known.scramble, 0xFF, MAX_KEY_REPEAT );
}

static void writeState( DCInfo *info, const char *fn ) {
	DCSaveState saveState;
	saveState.keySize = info->keySize;
	saveState.counter = info->counter;
	memcpy( &saveState.state.key, &info->state.key, MAX_KEY_REPEAT );
	memcpy( &saveState.state.scramble, &info->state.scramble, MAX_KEY_REPEAT );
	fopen_and_write( &saveState, sizeof(saveState), fn, "wb" );
}

static void usage(char *pname) {
	printf("Usage: %s [-k inkey] [-K outkey]\n"
	       "          [-s inscramble] [-S outscramble]\n"
	       "          [-o instate] [-O outstate]\n"
	       "          [-r bitrate] [-f frequency]\n"
	       "          [-p plaintext]\n"
	       "          [-e] <infile> [outfile]\n", pname);
	printf("\n");
}

int main(int argc, char *argv[]) {
	int status        = EXIT_FAILURE;

	const char *outStateFileName = NULL;
	FILE *outKey      = NULL;
	FILE *outScramble = NULL;
	FILE *inFile      = NULL;
	FILE *outFile     = NULL;
	FILE *plainText   = NULL;
	bool counterSet   = false;
	bool encrypt      = false;

	DCInfo *info = dcinfo_new();

	int c;
	while((c = getopt(argc, argv, "hk:K:s:S:c:o:O:p:r:f:e")) != -1) {
		switch(c) {
			case 'k':
				info->keySize = fopen_and_read( &info->state.key, MAX_KEY_REPEAT, optarg, "rb" ); 
				memset( &info->known.key, 0xFF, MAX_KEY_REPEAT );
				break;
			case 'K':
				outKey        = fopen_safe(optarg, "wb");
				break;
			case 's':
				info->keySize = fopen_and_read( &info->state.scramble, MAX_KEY_REPEAT, optarg, "rb" );
				memset( &info->known.scramble, 0xFF, MAX_KEY_REPEAT );
				break;
			case 'S':
				outScramble = fopen_safe(optarg, "wb");
				break;
			case 'o':
				readState( info, optarg );
				counterSet = true;
				break;
			case 'O': outStateFileName = optarg; break;
			case 'p': plainText   = fopen_safe(optarg, "rb"); break;
			case 'r': info->bitRate   = atoi(optarg); break;
			case 'f': info->frequency = atoi(optarg); break;
			case 'e': encrypt = true; break;
			case 'c': 
				info->counter = atoi(optarg);
				counterSet = true;
				break;
			case 'h':
			case '?':
				usage(argv[0]);
				goto done;
		}
	}
	if(optind < argc) inFile  = fopen_safe(argv[optind++], "rb");
	if(optind < argc) outFile = fopen_safe(argv[optind++], "wb");
	if(optind < argc || inFile == NULL) {
		usage(argv[0]);
		goto done;
	}

	info->data = fread_new(&info->size, inFile);
	fclose(inFile);
	inFile = NULL;

	if(!encrypt) {
		printf("Swapping bytes\n");
		swapBytes(info->data, info->size);
	}

	if (encrypt && (info->keySize == 0 || !counterSet)) {
		printf("Can't encrypt without key and counter\n");
		goto done;
	}

	dcinfo_calculateFrameInfo(info);
	printf("Frame size: %zu\n", info->frameSize);
	printf("Frame header: %08x\n", info->frameHeader);

	info->frameHeaders = findFrameHeaders(info->data, info->size, info->frameSize, &info->n_frameHeaders);
	findImpliedFrameHeaders(info);

	if(info->n_frameHeaders == 0) die("Could not detect any frame headers.");
	size_t maxFrameHeaders = info->size / info->frameSize, minFrameHeaders = info->size / (info->frameSize + 1);
	if(info->n_frameHeaders > maxFrameHeaders) die("Found %zu frame headers but file only has room for %zu.", info->n_frameHeaders, maxFrameHeaders);

retry:
	printf("Total %zu, max possible: %zu\n", info->n_frameHeaders, maxFrameHeaders);

	bool r = prepareCounterAndKey( info, counterSet, info->keySize != 0 );
	printf("r %s counter: %u keySize: %zu\n", r ? "true" : "false", info->counter, info->keySize );

	if(!r) die("Can't get counter");	

	if(info->n_frameHeaders < minFrameHeaders) {
		printf("Trying to find more implied frame headers...\n");
		findImpliedFrameHeaders(info);
		bool r = prepareCounterAndKey( info, true, true );
		printf("r %s counter: %u keySize: %zu\n", r ? "true" : "false", info->counter, info->keySize );
		printf("Total %zu, max possible: %zu\n", info->n_frameHeaders, maxFrameHeaders);
	}

	printf("Known scramble bits: %d/%zu\n", knownBits(info->known.scramble), info->keySize*8 );
	printf("Known key bits: %d/%zu\n", knownBits(info->known.key), info->keySize*8 );

	if(knownBits(info->known.scramble) < info->keySize*8 && plainText) {
		size_t ptSize;
		uint8_t *ptData = fread_new( &ptSize, plainText );
		if(ptSize != info->size) {
			printf("Ciphertext has length %zu but plaintext has length %zu\n", info->size, ptSize);
			goto done;
		}

		for(size_t i = 0; i < info->size-1; i += 2) {
			uint16_t ptw = ptData[i] << 8 | ptData[i+1];
			if(!deriveKey(info->data, i, ptw, 0xFFFF, info->counter, info->keySize, &info->state, &info->known)) {
				printf("blew up deriving key from plaintext!\n");

				// HACK HACK HACK HACK HACK
				static int baseKeySize = 0, keyMultiplier;
				if(baseKeySize == 0) {
					baseKeySize = info->keySize;
					keyMultiplier = 2;
				} else {
					keyMultiplier += 1;
				}
				if(baseKeySize * keyMultiplier <= MAX_KEY_REPEAT) {
					printf("Trying original key size (%d) * %d\n", baseKeySize, keyMultiplier);
					info->keySize = baseKeySize * keyMultiplier;
					fseek(plainText, 0, SEEK_SET);
					memset( &info->state, 0, sizeof(info->state) );
					memset( &info->known, 0, sizeof(info->known) );
					goto retry;
				} else {
					printf("Max key size tried, giving up.\n");
				}
				goto done;
			}
		}
	}

	if(knownBits(info->known.scramble) < info->keySize*8) {
		printf("Not enough scramble bits, looking for runs of 0x00 or 0xFF\n");
		DCState *orig_state = malloc(sizeof(DCState));
		DCState *orig_known = malloc(sizeof(DCState));

#if 0
		/* Last byte in file is always 0x00  */
		if(!deriveKey( data, size - 2, 0x0000, 0x00FF, state, known )) printf("Last byte not 0?\n");

		/* First byte after first frame header is always 0x00, next byte is always 0x0_  */
		size_t ffh = findNextFrameHeader(data, size, 0, 1);
		if(ffh%2==0) {
			if(!deriveKey( data, ffh+4, 0x0000, 0xFFF0, state, known )) printf("no 0 after first frame header?\n");
		} else {
			if(!deriveKey( data, ffh+3, 0x0000, 0x00FF, state, known )) printf("no 0 after first frame header?\n");;
			if(!deriveKey( data, ffh+7, 0x0000, 0xF000, state, known )) printf("no 0 after first frame header?\n");;
		}
#endif

		int ff = 0;
		for(int fie = 0; fie < 2; ++fie) {
			for(int minRunSize = 256; minRunSize >= 2; minRunSize /= 2) {
				printf("min run size: %d\n", minRunSize);
				for(uint16_t r = 0x0000; r != 0xFFFE; r += 0xFFFF) { // dumb hack: for r in [0x0000, 0xFFFF]
					for(size_t fhi = 0; fhi < info->n_frameHeaders; ++fhi) {
						size_t fi = info->frameHeaders[fhi];
						int adj = (fi%2==0) ? 0 : 1;
						for(size_t si = fi + 4+adj; si < fi + info->frameSize - minRunSize; si += 2) {
							int count = 0;
							memcpy( orig_state, &info->state, sizeof(DCState) );
							memcpy( orig_known, &info->known, sizeof(DCState) );
							for(size_t i = si; i < fi + info->frameSize - 1 && i < info->size - 1; i += 2) {
								if( deriveKey( info->data, i, r, 0xFFFF, info->counter, info->keySize, &info->state, &info->known ) ) {
									count++;
								} else {
									break;
								}
							}
							if(count < minRunSize) {
								memcpy( &info->state, orig_state, sizeof(DCState) );
								memcpy( &info->known, orig_known, sizeof(DCState) );
							} else {
								if(!fie) {
									memcpy( &info->state, orig_state, sizeof(DCState) );
									memcpy( &info->known, orig_known, sizeof(DCState) );
									for(size_t i = si + 2; i < si + (count*2) -2; i += 2) {
										deriveKey( info->data, i, r, 0xFFFF, info->counter, info->keySize, &info->state, &info->known );
									}
								}
								ff++;
							}
						}
						//if(knownBits(info->known.key) >= info->known.keySize*8) break; 
					}
				}
			}
		}

		free(orig_state);
		free(orig_known);

		printf("Found %d runs\n", ff);
	}

	printf("Known scramble bits: %d/%zu\n", knownBits(info->known.scramble), info->keySize*8 );
	printf("Known key bits: %d/%zu\n", knownBits(info->known.key), info->keySize*8 );

	printKnownBits( info->state.scramble, info->known.scramble );
	printKnownBits( info->state.key,      info->known.key );

	if(knownBits(info->known.scramble) < info->keySize*8 ||
		knownBits(info->known.key) < info->keySize*8) {
		printf("Incomplete key, not creating output.\n");
		goto done;
	}


	if(outKey      != NULL) writeFile( "key",      outKey,      info->state.key,      info->keySize  );
	if(outScramble != NULL) writeFile( "scramble", outScramble, info->state.scramble, info->keySize  );
	if(outStateFileName != NULL) writeState( info, outStateFileName );

	if(outFile!=NULL) {
		void * out = encrypt ? encryptData(info->data, info->size, info->counter, info->keySize, &info->state) : decryptData(info->data, info->size, info->counter, info->keySize, &info->state); 
		writeFile(encrypt ? "encrypted data" : "decrypted data", outFile, out, info->size);
		free(out);
	}

	status = EXIT_SUCCESS;

done:
	if(info) dcinfo_free(info);

	if(inFile) fclose(inFile);
	if(outFile) fclose(outFile);
	if(outKey) fclose(outKey);
	if(outScramble) fclose(outScramble);
	if(plainText) fclose(plainText);
	return status;
}




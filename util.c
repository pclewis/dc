#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "util.h"

void die(const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

size_t fread_safe(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	size_t read = fread(ptr, size, nmemb, stream);
	if(read != (size*nmemb)) die("Bad read: got %zu/%zu bytes.", read, (size*nmemb));
	return read;
}

void *fread_new(size_t *size, FILE *stream) {
	*size = fileSize(stream);
	void *ptr = malloc(*size);
	fread_safe(ptr, 1, *size, stream);
	return ptr;
}

FILE *fopen_safe(const char *fn, const char *mode) {
	FILE *fp = fopen(fn, mode);
	if(fp == NULL) die("Couldn't open %s: %s", fn, strerror(errno));
	return fp;
}

size_t fopen_and_read(void *ptr, size_t size, const char *fn, const char *mode) {
	FILE *fp = fopen_safe(fn, mode);
	size_t read = fread(ptr, 1, size, fp);
	fclose(fp);
	return read;
}

size_t fopen_and_write(void *ptr, size_t size, const char *fn, const char *mode) {
	FILE *fp = fopen_safe(fn, mode);
	size_t written = fwrite_safe(fp, ptr, size);
	fclose(fp);
	return written;
}

size_t fwrite_safe(FILE *fp, void *data, size_t size) {
	size_t written = fwrite(data, 1, size, fp);
	if(written != size) die("Bad write: wrote %zu/%zu bytes.", written, size);
	return written;
}

size_t fileSize(FILE *fp) {
	long start = ftell(fp);
	fseek(fp, 0, SEEK_END);
	long result = ftell(fp);
	fseek(fp, start, SEEK_SET);
	assert(result > 0);
	return result;
}

void *realloc_safe(void *ptr, size_t size) {
	void *result = realloc(ptr, size);
	if(result == NULL) die("Realloc failed. Requested size: %zu", size); // note ptr is unfreed
	return result;
}

void *calloc_safe(size_t nmemb, size_t size) {
	void *result = calloc(nmemb, size);
	if(result == NULL) die("Calloc failed. Requested size: %zu", nmemb*size);
	return result;
}
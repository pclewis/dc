#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

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
	if(read != size) die("Bad read: got %zu/%zu bytes.", read, size);
	return read;
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

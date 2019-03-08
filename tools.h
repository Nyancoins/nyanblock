#ifndef __H_TOOLS_
#define __H_TOOLS_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <openssl/sha.h>

#include "blockchain.h"

int array_compare_u8(const char* a, const char* b, size_t len);
int32_t swap_endian(int32_t v);
int sha256sum(unsigned char* dest, void *addr, const size_t len);
void double_sha256(unsigned char* dest, const void* addr, const size_t len);
void print_sha256sum(const unsigned char* hash);
int timeago(char *dest, size_t dest_maxlen, time_t unixtime);
double GetDifficulty(const uint32_t bits);
int snprint_sha256sum(char dest[65], const unsigned char* hash);

#endif

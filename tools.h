#ifndef __H_TOOLS_
#define __H_TOOLS_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

int array_compare_u8(const char* a, const char* b, size_t len);
int32_t swap_endian(int32_t v);
int timeago(char *dest, size_t dest_maxlen, time_t unixtime);
double GetDifficulty(const uint32_t bits);

#endif

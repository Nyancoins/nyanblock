#include "tools.h"

int array_compare_u8(const char* a, const char* b, size_t len) {
    int r = 0;

    for(int i = 0; i < len; ++i) {
        if(a[i] != b[i]) return -1;
    }

    return 0;
}

int32_t swap_endian(int32_t v) {
    int32_t swapped = ((v>>24)&0xff) | // move byte 3 to byte 0
                    ((v<<8)&0xff0000) | // move byte 1 to byte 2
                    ((v>>8)&0xff00) | // move byte 2 to byte 1
                    ((v<<24)&0xff000000); // byte 0 to byte 3
    return swapped;
}

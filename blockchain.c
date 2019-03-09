#include "blockchain.h"

uint64_t parse_varint(const uint8_t* varint) {
    uint8_t first;
    memcpy(&first, varint, sizeof(uint8_t));

    if(first <= 0xfc) return first;

    if(first == 0xfd) {
        uint16_t val;
        memcpy(&val, varint, sizeof(uint16_t));
        return val;
    }

    if(first == 0xfe) {
        uint32_t val;
        memcpy(&val, varint, sizeof(uint32_t));
        return val;
    }

    if(first == 0xff) {
        uint64_t val;
        memcpy(&val, varint, sizeof(uint64_t));
        return val;
    }

    return 0;
}
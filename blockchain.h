#ifndef __H_BLOCKHAIN_
#define __H_BLOCKHAIN_
#include <stdint.h>

typedef struct {
    int32_t version;
    uint8_t prev_block[32];
    uint8_t merkle_root[32];
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
    //char txn_count; //var_int
} __attribute__((aligned(1),packed)) t_BlockHeader;

typedef struct {
    uint8_t magic[4];
    uint32_t size;
    //t_BlockHeader *hdr;
} __attribute__((aligned(1),packed)) t_BlockDataHeader;


#endif

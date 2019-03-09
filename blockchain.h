#ifndef __H_BLOCKHAIN_
#define __H_BLOCKHAIN_
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

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


#define BLOCK_INPUT_TXID_LENGTH 32
typedef struct {
    uint8_t txid[BLOCK_INPUT_TXID_LENGTH];
    uint32_t txout;
    uint64_t scriptlen; // var_int
    uint8_t *script; // of scriptlen size
    uint32_t sequence;
} input_t;

typedef struct {
    uint64_t value;
    uint64_t pubkeylen; // var_int
    uint8_t *pubkey;
} output_t;

typedef struct {
    uint32_t version;
    uint64_t num_inputs; //var_int
    input_t **inputs; // of length num_inputs
    uint64_t num_outputs; // var_int
    output_t **outputs;
    uint32_t locktime;
} transaction_t;

size_t parse_varint(uint64_t *out, const uint8_t* varint);
size_t parse_transaction(transaction_t **data, const uint8_t* src);
void free_transaction(transaction_t *tx);


#endif

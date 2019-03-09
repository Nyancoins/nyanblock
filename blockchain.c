#include "blockchain.h"
#include "tools.h"

size_t parse_varint(uint64_t *out, const uint8_t* varint) {
    uint8_t first;
    memcpy(&first, varint, sizeof(uint8_t));

    if(first <= 0xfc) {
        *out = first;
        return sizeof(uint8_t);
    }

    if(first == 0xfd) {
        uint16_t val;
        memcpy(&val, varint, sizeof(uint16_t));
        return sizeof(uint16_t);
    }

    if(first == 0xfe) {
        uint32_t val;
        memcpy(&val, varint, sizeof(uint32_t));
        return sizeof(uint32_t);
    }

    if(first == 0xff) {
        uint64_t val;
        memcpy(&val, varint, sizeof(uint64_t));
        return sizeof(uint64_t);
    }

    return 0;
}

size_t parse_output(output_t *dest, uint8_t *pos) {
    const uint8_t *start = pos;

    memcpy(&dest->value, pos, sizeof(uint64_t)); pos +=  sizeof(uint64_t);
    pos += parse_varint(&dest->pubkeylen, pos);
    
    dest->pubkey = (uint8_t*)malloc(sizeof(uint8_t)*dest->pubkeylen);
    memcpy(dest->pubkey, pos, sizeof(uint8_t)*dest->pubkeylen); pos += sizeof(uint8_t)*dest->pubkeylen;


    return labs(pos - start);
}

size_t parse_input(input_t *dest, uint8_t* pos) {
    const uint8_t *start = pos;

    memcpy(&dest->txid, pos, sizeof(uint8_t)*BLOCK_INPUT_TXID_LENGTH); pos += sizeof(uint8_t)*BLOCK_INPUT_TXID_LENGTH;
    memcpy(&dest->txout, pos, sizeof(uint32_t)); pos += sizeof(uint32_t);
    pos += parse_varint(&dest->scriptlen, pos);

    dest->script = (uint8_t*)malloc(dest->scriptlen * sizeof(uint8_t));
    memcpy(dest->script, pos, dest->scriptlen); pos += dest->scriptlen;

    memcpy(&dest->sequence, pos, sizeof(uint32_t)); pos += sizeof(uint32_t);


    return labs(pos - start);
}


size_t parse_transaction(transaction_t **data, const uint8_t* src) {

    transaction_t *tx = malloc(sizeof(transaction_t));
    *data = tx;

    uint8_t *pos = (uint8_t*)src;

    memcpy(&tx->version, pos, sizeof(uint32_t)); pos += sizeof(uint32_t);
    //byte_swap((unsigned char*)&tx->version, sizeof(uint32_t));

    pos += parse_varint(&tx->num_inputs, pos);
    tx->inputs = (input_t**)malloc(tx->num_inputs*sizeof(input_t*));

    for(uint64_t i = 0; i < tx->num_inputs; ++i) {
        tx->inputs[i] = (input_t*)malloc(sizeof(input_t));
        pos += parse_input(tx->inputs[i], pos);
    }

    pos += parse_varint(&tx->num_outputs, pos);
    tx->outputs = (output_t**)malloc(tx->num_outputs*sizeof(output_t*));

    for(uint64_t i = 0; i < tx->num_outputs; ++i) {
        tx->outputs[i] = (output_t*)malloc(sizeof(output_t));
        pos += parse_output(tx->outputs[i], pos);
    }

    memcpy(&tx->locktime, pos, sizeof(uint32_t)); pos += sizeof(uint32_t);


    return labs(pos - src);
}

void free_transaction(transaction_t *tx) {
    for(uint64_t i = 0; i < tx->num_inputs; ++i) {
        free(tx->inputs[i]->script);
        free(tx->inputs[i]);
    }
    for(uint64_t i = 0; i < tx->num_outputs; ++i) {
        free(tx->outputs[i]->pubkey);
        free(tx->outputs[i]);
    }
    free(tx->inputs);
    free(tx->outputs);
    free(tx);
}


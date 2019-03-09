#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <wordexp.h>

#include "blockchain.h"
#include "tools.h"
#include "ansicolor.h"

static unsigned char NyanCoinMagic[4] = { 0xfc, 0xd9, 0xb7, 0xdd };


void print_block_dataheader(const t_BlockDataHeader* h) {
    printf("\tMagic: 0x");
    for(int i = 0; i < 4; ++i) {
        printf("%.2x", h->magic[i]);
    }

    if(array_compare_u8((const char*)h->magic, (const char*)NyanCoinMagic, 4) == 0) {
        printf(" - (nyancoin)");
    } else {
        printf(" - (no match?!)\n");
        return;
    }
    printf("\n");

    printf("\tSize: (0x%.8x) %u bytes\n", h->size, h->size);
}

void print_hash256(const uint8_t *buf) {
    for(int i = 0; i < 32; ++i) {
        printf("%.2x", buf[i]);
    }
}

static char timebuf[128];

void print_block_header(const t_BlockHeader* h) {
    printf("\tVersion: %d\n", h->version);
    printf("\tPrevBlock: "); print_hash256(h->prev_block); printf("\n");
    printf("\tMerkleRoot: "); print_hash256(h->merkle_root); printf("\n");
    
    timeago(timebuf, 127, h->timestamp);
    timebuf[127] = '\0';
    
    printf("\tTimeStamp: %d (%s)\n", h->timestamp, timebuf);

    double diff = GetDifficulty(h->bits);
    printf("\tBits: 0x%.8x (diff: %.8f)\n", h->bits, diff);
    printf("\tNonce: %u\n", h->nonce);
}


int main(int argc, char** argv) {
    FILE *f = fopen("blk0001.dat", "rb");
    if(!f) {
        wordexp_t exp_result;
        wordexp("~/.nyancoin/blk0001.dat", &exp_result, 0);
        f = fopen(exp_result.we_wordv[0], "rb");
        if(!f) {
            printf("Cannot open ./blk0001.dat or ~/.nyancoin/blk0001.dat!\n");
            exit(1);
        }
    }


    fseek(f, 0L, SEEK_END);
    size_t fileLen = ftell(f);
    printf("File is %lu bytes long.\n", fileLen);
    rewind(f);

    //char buf[1024];
    //int read = fread(buf, 1, 100, f);

    void* mappedFile = mmap(NULL, fileLen, PROT_READ, MAP_PRIVATE, fileno(f), 0);
    if(mappedFile == MAP_FAILED) {
        printf("\nFailed to mmap!\n");
        exit(1);
    }
    

    t_BlockDataHeader *h = (t_BlockDataHeader*)mappedFile;
    t_BlockHeader* bh = (void*)h + 8;


    // Scan blockchain
    uint64_t bid = -1;
    uint64_t offset = 0;
    unsigned char blockHash[SHA256_DIGEST_LENGTH];
    memset(blockHash, 0, SHA256_DIGEST_LENGTH);
    char blockHashStr[65], parentHashStr[65], merkleHashStr[65];
    blockHashStr[64] = '\0'; parentHashStr[64] = '\0'; merkleHashStr[64] = '\0'; 
    unsigned char temp[64];
    while(offset < fileLen) {
        h = (t_BlockDataHeader*)(mappedFile + offset);
        bh = (t_BlockHeader*)((void*)h + 8);
        ++bid;

        printf("\nBlock #%lu\n", bid);
        print_block_dataheader(h);
        printf("\t----\n");

        if(array_compare_u8((const char*)h->magic, (const char*)NyanCoinMagic, 4) != 0) {
            printf("\n" ANSI_COLOR_ALERT "Magic does not match any known values, cannot continue!" ANSI_COLOR_RESET "\n");
            break;
        }
        

        if(array_compare_u8((const char*)blockHash, (const char*)bh->prev_block, SHA256_DIGEST_LENGTH) == 0) {
            printf("\t" ANSI_COLOR_GREEN "[PreviousBlock hash match!]" ANSI_COLOR_RESET "\n");
        } else {
            printf("\t" ANSI_COLOR_ALERT "[!! PreviousBlock hash mismatch !!]" ANSI_COLOR_RESET "\n");
            print_block_header(bh);
            break;
        }

        double_sha256(blockHash, (void*)bh, sizeof(t_BlockHeader));
        memcpy(temp, blockHash, 32);
        byte_swap(temp, 32);
        snprint_sha256sum(blockHashStr, temp);
        
        memcpy(temp, bh->prev_block, 32);
        byte_swap(temp, 32);
        snprint_sha256sum(parentHashStr, temp);

        printf("\tBlockHeader hash: %s\n", blockHashStr);

        print_block_header(bh);


        // varint + tx
        const uint8_t* varint_base = (uint8_t*) bh + sizeof(t_BlockHeader);
        uint64_t val = parse_varint(varint_base);
        printf("\t---\n\tVarInt: %lu transaction%s\n", val, val > 1 ? "s" : "");


        // end of loop
        offset += h->size + 8;
    }

    munmap(mappedFile, fileLen);
    fclose(f);

    //getchar();
}
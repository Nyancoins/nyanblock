#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <openssl/sha.h>

#include "tools.h"

static unsigned char NyanCoinMagic[4] = { 0xfc, 0xd9, 0xb7, 0xdd };

typedef struct {
    int32_t version;
    uint8_t prev_block[32];
    uint8_t merkle_root[32];
    uint32_t timestamp;
    uint32_t bits;
    uint32_t nonce;
    //char txn_count; //var_int
} __attribute__((aligned(1),packed))  t_BlockHeader;

typedef struct {
    uint8_t magic[4];
    uint32_t size;
    //t_BlockHeader *hdr;
} __attribute__((aligned(1),packed)) t_BlockDataHeader;

void print_block_dataheader(const t_BlockDataHeader* h) {
    printf("\tMagic: 0x");
    for(int i = 0; i < 4; ++i) {
        printf("%.2x", h->magic[i]);
    }

    if(array_compare_u8(h->magic, NyanCoinMagic, 4) == 0) {
        printf(" - MATCH (nyancoin)");
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

void print_block_header(const t_BlockHeader* h) {
    printf("\tVersion: %d\n", h->version);
    printf("\tPrevBlock: "); print_hash256(h->prev_block); printf("\n");
    printf("\tMerkleRoot: "); print_hash256(h->merkle_root); printf("\n");
    printf("\tTimeStamp: %d\n", h->timestamp);
    printf("\tBits: 0x%.8x\n", h->bits);
    printf("\tNonce: %u\n", h->nonce);
}

unsigned char* sha256sum(unsigned char* dest, void *addr, const size_t len) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, addr, len);
    SHA256_Final(dest, &ctx);
}

void double_sha256(unsigned char* dest, const void* addr, const size_t len) {
    unsigned char firstHash[SHA256_DIGEST_LENGTH];
    sha256sum(firstHash, (void*)addr, len);
    sha256sum(dest, firstHash, SHA256_DIGEST_LENGTH);
}

void print_sha256sum(const unsigned char* hash) {
    for(int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        printf("%.2x", hash[i]);
    }
}

int main(int argc, char** argv) {
    FILE *f = fopen("blk0001.dat", "rb");
    fseek(f, 0L, SEEK_END);
    size_t fileLen = ftell(f);
    printf("File is %lu bytes long.\n", fileLen);
    rewind(f);

    //char buf[1024];
    //int read = fread(buf, 1, 100, f);

    void* mappedFile = mmap(NULL, fileLen, PROT_READ, MAP_PRIVATE|MAP_NORESERVE|MAP_NONBLOCK, fileno(f), 0);
    if(mappedFile == MAP_FAILED) {
        printf("\nFailed to mmap!\n");
        exit(1);
    }
    

    t_BlockDataHeader *h = (t_BlockDataHeader*)mappedFile;
    t_BlockHeader* bh = (void*)h + 8;


    // Scan blockchain
    uint64_t bid = 0;
    uint64_t offset = 0;
    unsigned char blockHash[SHA256_DIGEST_LENGTH];
    memset(blockHash, 0, SHA256_DIGEST_LENGTH);
    while(offset < fileLen) {
        h = (t_BlockDataHeader*)(mappedFile + offset);
        bh = (t_BlockHeader*)((void*)h + 8);
        ++bid;

        printf("Block #%lu\n", bid);
        print_block_dataheader(h);
        printf("\t----\n");

        if(array_compare_u8(h->magic, NyanCoinMagic, 4) != 0) {
            printf("\nMagic does not match any known values, cannot continue!\n");
            break;
        }

        

        if(array_compare_u8(blockHash, bh->prev_block, SHA256_DIGEST_LENGTH) == 0) {
            printf("\t[PreviousBlock hash match!]\n");
        } else {
            printf("\t[!! PreviousBlock hash mismatch !!]\n");
            print_block_header(bh);
            exit(1);
        }

        double_sha256(blockHash, (void*)bh, sizeof(t_BlockHeader));
        printf("\tBlockHeader hash: "); print_sha256sum(blockHash); printf("\n");

        print_block_header(bh);

        // end of loop
        offset += h->size + 8;
    }

    //getchar();
}
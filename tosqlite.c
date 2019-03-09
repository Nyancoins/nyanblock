#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <wordexp.h>
#include <signal.h>

#include <sqlite3.h>

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

static volatile int keepgoing = 1;

void sigint_handler(int sig) {
    keepgoing = 0;
    fprintf(stderr, "SIGINT captured!\n");
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

    signal(SIGINT, sigint_handler);

    //char buf[1024];
    //int read = fread(buf, 1, 100, f);

    void* mappedFile = mmap(NULL, fileLen, PROT_READ, MAP_PRIVATE, fileno(f), 0);
    if(mappedFile == MAP_FAILED) {
        printf("\nFailed to mmap!\n");
        exit(1);
    }

    char *sqlerr;
    int ok = 666;
    sqlite3 *db;
    if(sqlite3_open_v2("nyanblock.db", &db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
        fprintf(stderr, "Unable to open nyanblock.db for writing!\n");
        exit(1);
    }

    if(sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS `blocks` ("
	"`id`	INTEGER PRIMARY KEY AUTOINCREMENT,"
    "`size` INTEGER NOT NULL,"
	"`version`	INTEGER NOT NULL,"
	"`parent_hash`	TEXT NOT NULL,"
    "`block_hash`   TEXT NOT NULL,"
	"`merkle_hash`	TEXT NOT NULL,"
	"`timestamp`	INTEGER NOT NULL,"
	"`bits`	INTEGER NOT NULL,"
	"`nonce`	INTEGER NOT NULL"
");"
"CREATE INDEX IF NOT EXISTS `idx_block_hash` ON `blocks` ("
"   `block_hash`"
");"
"CREATE INDEX IF NOT EXISTS `idx_parent_hash` ON `blocks` ("
"	`parent_hash`"
");", NULL, NULL, &sqlerr) != SQLITE_OK) {
    printf("Could not initialize sqlite database!\nReason: %s\n", sqlerr);
    exit(1);
}

    sqlite3_stmt *block_insert_stmt;
    ok = sqlite3_prepare(db,
        "INSERT INTO blocks (id, version, block_hash, parent_hash, merkle_hash, timestamp, bits, nonce, size) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    -1, &block_insert_stmt, NULL);
    if(ok != SQLITE_OK) {
        printf("Unable to prepare statement! (%d)\nBecause: %s\n", ok, sqlite3_errmsg(db));
        exit(1);
    }
    sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL);
    

    t_BlockDataHeader *h = (t_BlockDataHeader*)mappedFile;
    t_BlockHeader* bh = (void*)h + 8;


    // Scan blockchain
    uint64_t bid = -1;
    uint64_t offset = 0;
    unsigned char blockHash[SHA256_DIGEST_LENGTH];
    char blockHashStr[65], parentHashStr[65], merkleHashStr[65];
    blockHashStr[64] = '\0'; parentHashStr[64] = '\0'; merkleHashStr[64] = '\0'; 
    unsigned char temp[64];
    memset(blockHash, 0, SHA256_DIGEST_LENGTH);
    while(offset < fileLen && keepgoing == 1) {
        h = (t_BlockDataHeader*)(mappedFile + offset);
        bh = (t_BlockHeader*)((void*)h + 8);
        ++bid;

        if(bid % 10000 == 0) {
            printf("Block #%lu\n", bid);
        }

        if(array_compare_u8((const char*)h->magic, (const char*)NyanCoinMagic, 4) != 0) {
            printf("\n" ANSI_COLOR_ALERT "Magic does not match any known values, cannot continue!" ANSI_COLOR_RESET "\n");
            break;
        }

        double_sha256(blockHash, (void*)bh, sizeof(t_BlockHeader));
        
        memcpy(temp, blockHash, 32);
        byte_swap(temp, 32);
        snprint_sha256sum(blockHashStr, temp);
        
        memcpy(temp, bh->prev_block, 32);
        byte_swap(temp, 32);
        snprint_sha256sum(parentHashStr, temp);

        memcpy(temp, bh->merkle_root, 32);
        byte_swap(temp, 32);
        snprint_sha256sum(merkleHashStr, temp);

        ok = sqlite3_bind_int(block_insert_stmt, 1, bid);
        if(ok != SQLITE_OK) { fprintf(stderr, "Unable to bind value to prepared statement. :( (%d)\n", ok); break; }
        ok = sqlite3_bind_int(block_insert_stmt, 2, bh->version);
        if(ok != SQLITE_OK) { fprintf(stderr, "Unable to bind value to prepared statement. :( (%d)\n", ok); break; }
        ok = sqlite3_bind_text(block_insert_stmt, 3, blockHashStr, -1, NULL);
        if(ok != SQLITE_OK) { fprintf(stderr, "Unable to bind value to prepared statement. :( (%d)\n", ok); break; }
        ok = sqlite3_bind_text(block_insert_stmt, 4, parentHashStr, -1, NULL);
        if(ok != SQLITE_OK) { fprintf(stderr, "Unable to bind value to prepared statement. :( (%d)\n", ok); break; }
        ok = sqlite3_bind_text(block_insert_stmt, 5, merkleHashStr, -1, NULL);
        if(ok != SQLITE_OK) { fprintf(stderr, "Unable to bind value to prepared statement. :( (%d)\n", ok); break; }
        ok = sqlite3_bind_int64(block_insert_stmt, 6, bh->timestamp);
        if(ok != SQLITE_OK) { fprintf(stderr, "Unable to bind value to prepared statement. :( (%d)\n", ok); break; }
        ok = sqlite3_bind_int64(block_insert_stmt, 7, bh->bits);
        if(ok != SQLITE_OK) { fprintf(stderr, "Unable to bind value to prepared statement. :( (%d)\n", ok); break; }
        ok = sqlite3_bind_int64(block_insert_stmt, 8, bh->nonce);
        if(ok != SQLITE_OK) { fprintf(stderr, "Unable to bind value to prepared statement. :( (%d)\n", ok); break; }
        ok = sqlite3_bind_int64(block_insert_stmt, 9, h->size);
        if(ok != SQLITE_OK) { fprintf(stderr, "Unable to bind value to prepared statement. :( (%d)\n", ok); break; }

        ok = sqlite3_step(block_insert_stmt);
        if(ok != SQLITE_OK && ok != SQLITE_DONE) { fprintf(stderr, "Unable to execute prepared statement. :( (%d)\nBecause: %s\n", ok, sqlite3_errmsg(db)); break; }

        sqlite3_reset(block_insert_stmt);

        /*printf("\nBlock #%lu\n", bid);
        print_block_dataheader(h);
        printf("\t----\n");

        if(array_compare_u8((const char*)blockHash, (const char*)bh->prev_block, SHA256_DIGEST_LENGTH) == 0) {
            printf("\t" ANSI_COLOR_GREEN "[PreviousBlock hash match!]" ANSI_COLOR_RESET "\n");
        } else {
            printf("\t" ANSI_COLOR_ALERT "[!! PreviousBlock hash mismatch !!]" ANSI_COLOR_RESET "\n");
            print_block_header(bh);
        }

        double_sha256(blockHash, (void*)bh, sizeof(t_BlockHeader));
        printf("\tBlockHeader hash: "); print_sha256sum(blockHash); printf("\n");

        print_block_header(bh);*/

        // end of loop
        offset += h->size + 8;
    }
    sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL);

    sqlite3_close(db);
    munmap(mappedFile, fileLen);
    fclose(f);

    //getchar();
}
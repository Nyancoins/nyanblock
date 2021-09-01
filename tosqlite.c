#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <wordexp.h>
#include <signal.h>
#include <unistd.h> // for isatty

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


char *sqlerr;
int ok = 666;
sqlite3 *db;

void sqlite_errcheck(int result, int fatal, const char *file, const int line) {
    if(result != SQLITE_OK && result != SQLITE_ROW && result != SQLITE_DONE) {
        char* ccstart = "";
        char* ccend = "";

        if(isatty(fileno(stderr))) {
            ccstart = ANSI_COLOR_RED;
            ccend = ANSI_COLOR_RESET;
        }

        fprintf(stderr, "%s%s:%d - SQLite error %d: %s%s\n", ccstart, file, line, result, sqlite3_errmsg(db), ccend);
        if(fatal != 0) {
            keepgoing = 0;
            fprintf(stderr, "%sCannot continue.%s\n", ccstart, ccend);
        }
    }
}

#define SQLITE_CHECK_FATAL(r) \
    sqlite_errcheck(r, 1, __FILE__, __LINE__);

int main(int argc, char** argv) {
    FILE *f = fopen("blk0001.dat", "rb");
    if(!f) {
        wordexp_t exp_result;
        wordexp("~/.nyancoin/blk0001.dat", &exp_result, 0);
        f = fopen(exp_result.we_wordv[0], "rb");
        wordfree(&exp_result);
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
        fprintf(stderr, ANSI_COLOR_RED "\nFailed to mmap!\n" ANSI_COLOR_RESET);
        exit(1);
    }

    ok = sqlite3_open_v2("nyanblock.db", &db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL);
    SQLITE_CHECK_FATAL(ok);
    if(ok != SQLITE_OK) exit(1);

    {
        FILE *sql = fopen("nyanblock.sql", "r");
        if (sql == NULL) {
            printf("unable to open nyanblock.sql\n");
            exit(1);
        }
        char buf[4096] = {0};
        fread(buf, 4095, 1, sql);
        fclose(sql);
        ok = sqlite3_exec(db, buf, NULL, NULL, &sqlerr); SQLITE_CHECK_FATAL(ok);
        if(ok != SQLITE_OK) exit(1);
    }



    sqlite3_stmt *block_insert_stmt;
    ok = sqlite3_prepare(db,
        "INSERT INTO blocks (id, version, block_hash, parent_hash, merkle_hash, timestamp, bits, nonce, size) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    -1, &block_insert_stmt, NULL);
    SQLITE_CHECK_FATAL(ok);


    sqlite3_stmt *transaction_insert_stmt;
    ok = sqlite3_prepare(db,
                         "INSERT INTO transactions (block, numtx) "
                         "VALUES (?, ?)",
                         -1, &transaction_insert_stmt, NULL);
    SQLITE_CHECK_FATAL(ok);

    sqlite3_stmt *inputs_insert_stmt;
    ok = sqlite3_prepare(db,
                         "INSERT INTO inputs (transaction_id, txhash, txout, script, sequence) "
                         "VALUES (?, ?, ?, ?, ?)",
                         -1, &inputs_insert_stmt, NULL);
    SQLITE_CHECK_FATAL(ok);

    sqlite3_stmt *outputs_insert_stmt;
    ok = sqlite3_prepare(db,
                         "INSERT INTO outputs (transaction_id, value, pubkey) "
                         "VALUES (?, ?, ?)",
                         -1, &outputs_insert_stmt, NULL);
    SQLITE_CHECK_FATAL(ok);
    

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

    ok = sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL); SQLITE_CHECK_FATAL(ok);

    while(offset < fileLen && keepgoing == 1) {
        h = (t_BlockDataHeader*)(mappedFile + offset);
        bh = (t_BlockHeader*)((void*)h + 8);
        ++bid;

        if(bid % 10000 == 0) {
            printf("Block #%llu\n", bid);
            ok = sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL); SQLITE_CHECK_FATAL(ok);
            ok = sqlite3_exec(db, "BEGIN TRANSACTION;", NULL, NULL, NULL); SQLITE_CHECK_FATAL(ok);
        }

        if(array_compare_u8((const char*)h->magic, (const char*)NyanCoinMagic, 4) != 0) {
            fprintf(stderr, "\n" ANSI_COLOR_ALERT "Magic does not match any known values, cannot continue!" ANSI_COLOR_RESET "\n");
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

        ok = sqlite3_bind_int(block_insert_stmt, 1, bid); SQLITE_CHECK_FATAL(ok);
        ok = sqlite3_bind_int(block_insert_stmt, 2, bh->version); SQLITE_CHECK_FATAL(ok);
        ok = sqlite3_bind_text(block_insert_stmt, 3, blockHashStr, -1, NULL); SQLITE_CHECK_FATAL(ok);
        ok = sqlite3_bind_text(block_insert_stmt, 4, parentHashStr, -1, NULL); SQLITE_CHECK_FATAL(ok);
        ok = sqlite3_bind_text(block_insert_stmt, 5, merkleHashStr, -1, NULL); SQLITE_CHECK_FATAL(ok);
        ok = sqlite3_bind_int64(block_insert_stmt, 6, bh->timestamp); SQLITE_CHECK_FATAL(ok);
        ok = sqlite3_bind_int64(block_insert_stmt, 7, bh->bits); SQLITE_CHECK_FATAL(ok);
        ok = sqlite3_bind_int64(block_insert_stmt, 8, bh->nonce); SQLITE_CHECK_FATAL(ok);
        ok = sqlite3_bind_int64(block_insert_stmt, 9, h->size); SQLITE_CHECK_FATAL(ok);

        ok = sqlite3_step(block_insert_stmt); SQLITE_CHECK_FATAL(ok);
        ok = sqlite3_reset(block_insert_stmt); SQLITE_CHECK_FATAL(ok);

        // varint + tx
        const uint8_t* varint_base = (uint8_t*) bh + sizeof(t_BlockHeader);
        uint8_t *pos = (uint8_t*)varint_base;
        uint64_t numTx = 0;
        size_t varint_len = parse_varint(&numTx, varint_base);
        pos += varint_len;
        //printf("\t---\n\tVarInt: %lu transaction%s\n", numTx, numTx > 1 ? "s" : "");

        ok = sqlite3_bind_int64(transaction_insert_stmt, 1, bid); SQLITE_CHECK_FATAL(ok);
        ok = sqlite3_bind_int64(transaction_insert_stmt, 2, numTx); SQLITE_CHECK_FATAL(ok);
        ok = sqlite3_step(transaction_insert_stmt); SQLITE_CHECK_FATAL(ok);
        ok = sqlite3_reset(transaction_insert_stmt); SQLITE_CHECK_FATAL(ok);
        uint64_t transaction_id = sqlite3_last_insert_rowid(db);

        for(uint64_t txid = 0; txid < numTx; ++txid) {
            //printf("\tTx: %lu ->\n", txid);

            transaction_t *tx;
            size_t txbytes = parse_transaction(&tx, pos);
            pos += txbytes;


            for(uint64_t ii = 0; ii < tx->num_inputs; ++ii) {
                const input_t *input = tx->inputs[ii];
                char txhash[65];
                memcpy(temp, input->txid, 32);
                byte_swap(temp, 32);
                snprint_sha256sum(txhash, temp);


                ok = sqlite3_bind_int64(inputs_insert_stmt, 1, transaction_id); SQLITE_CHECK_FATAL(ok);
                ok = sqlite3_bind_text(inputs_insert_stmt, 2, txhash, 64, SQLITE_STATIC); SQLITE_CHECK_FATAL(ok);
                ok = sqlite3_bind_int(inputs_insert_stmt, 3, input->txout); SQLITE_CHECK_FATAL(ok);
                ok = sqlite3_bind_blob(inputs_insert_stmt, 4, input->script, input->scriptlen, SQLITE_STATIC); SQLITE_CHECK_FATAL(ok);
                ok = sqlite3_bind_int(inputs_insert_stmt, 5, input->sequence); SQLITE_CHECK_FATAL(ok);
                ok = sqlite3_step(inputs_insert_stmt); SQLITE_CHECK_FATAL(ok);
                ok = sqlite3_reset(inputs_insert_stmt); SQLITE_CHECK_FATAL(ok);
            }
            //printf("\n");

            for(uint64_t ii = 0; ii < tx->num_outputs; ++ii) {
                const output_t *output = tx->outputs[ii];

                ok = sqlite3_bind_int64(outputs_insert_stmt, 1, transaction_id); SQLITE_CHECK_FATAL(ok);
                ok = sqlite3_bind_int64(outputs_insert_stmt, 2, (uint64_t)output->value); SQLITE_CHECK_FATAL(ok);
                ok = sqlite3_bind_blob(outputs_insert_stmt, 3, output->pubkey, output->pubkeylen, SQLITE_STATIC); SQLITE_CHECK_FATAL(ok);
                ok = sqlite3_step(outputs_insert_stmt); SQLITE_CHECK_FATAL(ok);
                ok = sqlite3_reset(outputs_insert_stmt); SQLITE_CHECK_FATAL(ok);
            }

            free_transaction(tx);
        }

        // end of loop
        offset += h->size + 8;
    }
    ok = sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL); SQLITE_CHECK_FATAL(ok);

    ok = sqlite3_finalize(block_insert_stmt); SQLITE_CHECK_FATAL(ok);
    ok = sqlite3_finalize(transaction_insert_stmt); SQLITE_CHECK_FATAL(ok);
    ok = sqlite3_finalize(inputs_insert_stmt); SQLITE_CHECK_FATAL(ok);
    ok = sqlite3_finalize(outputs_insert_stmt); SQLITE_CHECK_FATAL(ok);
    ok = sqlite3_close(db); SQLITE_CHECK_FATAL(ok);
    munmap(mappedFile, fileLen);
    fclose(f);

    //getchar();
}
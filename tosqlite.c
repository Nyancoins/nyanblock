#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <glob.h>
#include <signal.h>
#include <unistd.h> // for isatty
#include <errno.h>

#include <sqlite3.h>

#include "blockchain.h"
#include "tools.h"
#include "ansicolor.h"

#ifndef MADV_SEQUENTIAL
#define MADV_SEQUENTIAL POSIX_MADV_SEQUENTIAL
#endif
#ifndef MADV_WILLNEED
#define MADV_WILLNEED POSIX_MADV_WILLNEED
#endif
#ifndef madvise
#define madvise posix_madvise
#endif

static unsigned char NyanCoinMagic[4] = { 0xfc, 0xd9, 0xb7, 0xdd };

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
    glob_t globr;
    int globresult = 0;
    if (globresult = glob("blk*.dat", 0, NULL, &globr) && globresult != 0) {
        fprintf(stderr, ANSI_COLOR_RED "Error resolving wordexp: %d\n" ANSI_COLOR_RESET, globresult);
        exit(1);
    }
    size_t numBlkFiles = globr.gl_pathc;
    if (numBlkFiles <= 0) {
        fprintf(stderr, ANSI_COLOR_RED "No blk*.dat files found in current directory!\n" ANSI_COLOR_RESET);
        exit(1);
    }

    signal(SIGINT, sigint_handler);

    ok = sqlite3_open_v2("nyanblock.db", &db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL);
    SQLITE_CHECK_FATAL(ok);
    if(ok != SQLITE_OK) exit(1);

    {
        FILE *sql = fopen("nyanblock.sql", "r");
        if (sql == NULL) {
            fprintf(stderr, ANSI_COLOR_RED "unable to open nyanblock.sql\n" ANSI_COLOR_RESET);
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

    sqlite3_stmt *block_exists_stmt;
    ok = sqlite3_prepare(db,
                         "SELECT id FROM blocks WHERE block_hash = ?",
                         -1, &block_exists_stmt, NULL);
    SQLITE_CHECK_FATAL(ok);
    
    for (uint64_t n = 0; n < numBlkFiles; ++n) {
        FILE *f = fopen(globr.gl_pathv[n], "rb");
        if(!f) {
            fprintf(stderr, ANSI_COLOR_RED "Cannot open %s!\n" ANSI_COLOR_RESET, globr.gl_pathv[n]);
            exit(1);
        }
        fprintf(stderr, ANSI_COLOR_GREEN "Opened blk file: %s\n" ANSI_COLOR_RESET, globr.gl_pathv[n]);

        fseek(f, 0L, SEEK_END);
        size_t fileLen = ftell(f);
        fprintf(stderr, "File is %lu bytes long.\n", fileLen);
        rewind(f);

        void* mappedFile = mmap(NULL, fileLen, PROT_READ, MAP_PRIVATE, fileno(f), 0);
        if(mappedFile == MAP_FAILED) {
            fprintf(stderr, ANSI_COLOR_RED "\nFailed to mmap: errno: %d\n" ANSI_COLOR_RESET, errno);
            exit(1);
        }

        if ( madvise(mappedFile, fileLen, MADV_SEQUENTIAL|MADV_WILLNEED) != 0 ) {
            fprintf(stderr, ANSI_COLOR_YELLOW "Not critical: Failed to madvise memory region" ANSI_COLOR_RESET "\n");
        }

        t_BlockDataHeader *h = (t_BlockDataHeader*)mappedFile;
        t_BlockHeader* bh = (void*)h + 8;


        // Scan blockchain
        uint64_t bid = -1;
        uint64_t offset = 0;
        uint64_t blocksSkipped = 0;
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
                printf("Block #%lu, %lu blocks skipped\n", bid, blocksSkipped);
                blocksSkipped = 0;
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

            {
                // check for existing blocks in database
                ok = sqlite3_bind_text(block_exists_stmt, 1, blockHashStr, 64, NULL); SQLITE_CHECK_FATAL(ok);
                ok = sqlite3_step(block_exists_stmt); SQLITE_CHECK_FATAL(ok);
                //fprintf(stderr, "%s  Block check %s ok: %d%s\n", ANSI_COLOR_RED, blockHashStr, ok, ANSI_COLOR_RESET);
                if (ok == SQLITE_ROW) {
                    // something exists, just continue
                    //fprintf(stderr, "%sSkipping block ...%s\n", ANSI_COLOR_MAGENTA, ANSI_COLOR_RESET);
                    blocksSkipped++;
                    sqlite3_reset(block_exists_stmt);
                    goto nextblock;
                }
                sqlite3_reset(block_exists_stmt);
            }
            
            memcpy(temp, bh->prev_block, 32);
            byte_swap(temp, 32);
            snprint_sha256sum(parentHashStr, temp);

            memcpy(temp, bh->merkle_root, 32);
            byte_swap(temp, 32);
            snprint_sha256sum(merkleHashStr, temp);

            ok = sqlite3_bind_int(block_insert_stmt, 1, bid); SQLITE_CHECK_FATAL(ok);
            ok = sqlite3_bind_int(block_insert_stmt, 2, bh->version); SQLITE_CHECK_FATAL(ok);
            ok = sqlite3_bind_text(block_insert_stmt, 3, blockHashStr, 64, NULL); SQLITE_CHECK_FATAL(ok);
            ok = sqlite3_bind_text(block_insert_stmt, 4, parentHashStr, 64, NULL); SQLITE_CHECK_FATAL(ok);
            ok = sqlite3_bind_text(block_insert_stmt, 5, merkleHashStr, 64, NULL); SQLITE_CHECK_FATAL(ok);
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
            nextblock:
            offset += h->size + 8;
        }
        ok = sqlite3_exec(db, "END TRANSACTION;", NULL, NULL, NULL); SQLITE_CHECK_FATAL(ok);
        munmap(mappedFile, fileLen);
        fclose(f);
    }

    
    globfree(&globr);
    ok = sqlite3_finalize(block_insert_stmt); SQLITE_CHECK_FATAL(ok);
    ok = sqlite3_finalize(transaction_insert_stmt); SQLITE_CHECK_FATAL(ok);
    ok = sqlite3_finalize(inputs_insert_stmt); SQLITE_CHECK_FATAL(ok);
    ok = sqlite3_finalize(outputs_insert_stmt); SQLITE_CHECK_FATAL(ok);
    ok = sqlite3_finalize(block_exists_stmt); SQLITE_CHECK_FATAL(ok);
    ok = sqlite3_close(db); SQLITE_CHECK_FATAL(ok);
}
BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS "blocks" (
	"id" INTEGER,
	"size" INTEGER NOT NULL,
	"version" INTEGER NOT NULL,
	"parent_hash" TEXT NOT NULL,
	"block_hash" TEXT NOT NULL,
	"merkle_hash" TEXT NOT NULL,
	"timestamp" INTEGER NOT NULL,
	"bits" INTEGER NOT NULL,
	"nonce" INTEGER NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);

CREATE INDEX IF NOT EXISTS "idx_block_hash" ON "blocks" ("block_hash");
CREATE INDEX IF NOT EXISTS "idx_parent_hash" ON "blocks" ("parent_hash");

CREATE TABLE IF NOT EXISTS "transactions" (
	"id" INTEGER,
	"block" INTEGER NOT NULL,
	"numtx" INTEGER NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT),
	FOREIGN KEY (block) REFERENCES blocks(id)
);

CREATE INDEX IF NOT EXISTS "idx_tx_block" ON "transactions" ("block");

CREATE TABLE IF NOT EXISTS "inputs" (
	"id" INTEGER,
	"transaction_id" INTEGER NOT NULL,
	"txhash" TEXT NOT NULL,
	"txout" INTEGER NOT NULL,
	"script" BLOB NOT NULL,
	"sequence" INTEGER NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT),
	FOREIGN KEY (transaction_id) REFERENCES transactions(id)
);

CREATE INDEX IF NOT EXISTS "idx_txhash_inputs" ON "inputs" ("txhash");
CREATE INDEX IF NOT EXISTS "idx_txid_inputs" ON "inputs" ("transaction_id");

CREATE TABLE IF NOT EXISTS "outputs" (
	"id" INTEGER NOT NULL,
	"transaction_id" INTEGER NOT NULL,
	"value" INTEGER NOT NULL,
	"pubkey" BLOB NOT NULL,
	PRIMARY KEY("id"),
	FOREIGN KEY (transaction_id) REFERENCES transactions(id)
);

CREATE INDEX IF NOT EXISTS "idx_txid_outputs" ON "outputs" ("transaction_id");
CREATE INDEX IF NOT EXISTS "idx_value_outputs" ON "outputs" ("value");


CREATE VIEW IF NOT EXISTS "blockchain" AS
	SELECT * FROM `blocks`
	INNER JOIN `transactions` ON transactions.block = blocks.id
	INNER JOIN `inputs` ON inputs.transaction_id = transactions.id
	INNER JOIN `outputs` ON outputs.transaction_id = transactions.id
;

COMMIT;
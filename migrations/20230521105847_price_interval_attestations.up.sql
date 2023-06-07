CREATE TABLE price_interval_attestations (
    validator_public_key TEXT NOT NULL,
    signature TEXT NOT NULL PRIMARY KEY,
    slot_number  BIGINT NOT NULL,
    value  BIGINT NOT NULL,
    interval_size  BIGINT NOT NULL
);

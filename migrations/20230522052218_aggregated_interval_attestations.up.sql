-- Add up migration script here
CREATE TABLE aggregate_interval_attestations (
    aggregate_signature text NOT NULL PRIMARY KEY,
    aggregate_public_key text NOT NULl,
    slot_number  BIGINT NOT NULL,
    value  BIGINT NOT NULL,
    interval_size  BIGINT NOT NULL,
    num_validators  BIGINT NOT NULL
);

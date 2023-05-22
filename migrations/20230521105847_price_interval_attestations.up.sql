-- Add up migration script here
CREATE TABLE price_interval_attestations (
    validator_public_key text NOT NULL,
    signature text NOT NULL PRIMARY KEY,
    slot_number integer NOT NULL,
    value integer NOT NULL,
    interval_size integer NOT NULL
);

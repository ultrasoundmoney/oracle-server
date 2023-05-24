-- Add up migration script here
CREATE TABLE aggregate_interval_attestations (
    aggregate_signature text NOT NULL PRIMARY KEY,
    aggregate_public_key text NOT NULl,
    slot_number integer NOT NULL,
    value integer NOT NULL,
    interval_size integer NOT NULL,
    num_validators integer NOT NULL
);

-- Add migration script here
CREATE TABLE price_value_attestations (
    validator_public_key text NOT NULL,
    slot_number integer NOT NULL,
    value integer NOT NULL,
    PRIMARY KEY (validator_public_key, slot_number)
);


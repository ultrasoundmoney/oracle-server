-- Add migration script here
CREATE TABLE price_value_attestations (
    validator_public_key text NOT NULL,
    slot_number BIGINT NOT NULL,
    value BIGINT NOT NULL,
    signature text NOT NULL,
    PRIMARY KEY (validator_public_key, slot_number)
);


CREATE TABLE price_value_attestations (
    validator_public_key TEXT NOT NULL,
    slot_number BIGINT NOT NULL,
    value BIGINT NOT NULL,
    signature TEXT NOT NULL,
    PRIMARY KEY (validator_public_key, slot_number)
);


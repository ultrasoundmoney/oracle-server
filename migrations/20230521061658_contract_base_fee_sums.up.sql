-- Add migration script here
CREATE TABLE contract_base_fee_sums (
	contract_address text PRIMARY KEY,
	base_fee_sum float NOT NULL,
	base_fee_sum_usd float
);


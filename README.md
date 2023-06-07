# Ultra Sound Oracle

Centralized server to store, validate and aggregate messages sent by validators running the ultrasound [oracle-client](https://github.com/ultrasoundmoney/oracle-client).

# Prerequesites
Except for the "Docker compose" option below, all commands require a running postgres db, the URI of which should be stored in the `DATABASE_URL` environment variable.
Also all commands in the "Cargo" section assume rust and cargo to be installed locally, whereas the "Docker" and "Docker compose" options can be run with only Docker installed. 

# Commands

## Cargo 
### Check
`cargo check`
### Run tests
`cargo test`
### Run dev server
`cargo run --bin server`

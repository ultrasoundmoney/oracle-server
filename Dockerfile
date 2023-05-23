FROM lukemathwalker/cargo-chef:latest-rust-latest AS chef
WORKDIR /app

FROM chef AS planner
COPY ./src ./src
COPY ./Cargo.toml ./Cargo.toml
# Figure out if dependencies have changed.
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this layer is cached for massive speed up.
RUN cargo chef cook --release --recipe-path recipe.json
# Build application - this should be re-done every time we update our src.
COPY ./src ./src
COPY ./migrations ./migrations
COPY ./Cargo.toml ./Cargo.toml
ENV DATABASE_URL=sqlite://sqlite.db
RUN cargo install sqlx-cli
RUN sqlx database create
RUN sqlx migrate run
RUN cargo build --release

FROM debian:bullseye-slim AS runtime
WORKDIR /app
# sqlx depends on native TLS, which is missing in buster-slim.
RUN apt update && apt install -y libssl1.1 ca-certificates sqlite3 libsqlite3-dev
COPY --from=builder /app/target/release/server /usr/local/bin
COPY --from=builder /app/sqlite.db .
ENV RUST_LOG=info
ENV DATABASE_URL=sqlite://sqlite.db

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/server"]



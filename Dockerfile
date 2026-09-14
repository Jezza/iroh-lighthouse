FROM rust:1-bookworm AS builder

WORKDIR /app
COPY . .

# Build server
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/iroh-lighthouse-server /
EXPOSE 3001
CMD ["/iroh-lighthouse-server"]

FROM rust:1.86-bullseye AS builder

WORKDIR /build

COPY . .

RUN cargo build --release

# Final stage
FROM debian:bullseye-slim
WORKDIR /app

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# 👇 Update path to match fixed layout
COPY --from=builder /build/target/release/axum /app/

CMD ["./axum"]

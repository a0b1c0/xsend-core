# xsend-core

Core Rust daemon and transfer engine for xSend.

This repository only contains core code:

- daemon runtime
- LAN/WAN transfer pipeline
- discovery/session/protocol modules
- local API and metrics

## Run

```bash
cargo run
```

## Test

```bash
cargo test
```

## Layout

- `src/` core daemon and transfer logic
- `Cargo.toml` crate manifest
- `Cargo.lock` lockfile

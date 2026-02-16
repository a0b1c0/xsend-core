# xSend Desktop (Tauri 2)

This folder contains a minimal **Tauri 2** desktop wrapper for xSend.

It starts the local xSend daemon (random localhost port) and opens the daemon UI inside a WebView,
so end users do not need to copy/paste ports or tokens.

## Run (dev)

```bash
cargo run --manifest-path desktop/src-tauri/Cargo.toml
```

## Build (bundle)

Tauri bundling requires the Tauri CLI and platform-specific toolchains.

```bash
cargo tauri build --manifest-path desktop/src-tauri/Cargo.toml
```


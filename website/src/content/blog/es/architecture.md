---
title: "The Architecture of a Secure P2P File Transfer System"
description: "Deep dive into how xSend uses Rust, Tokio, and X25519 to deliver secure, high-performance file transfers."
pubDate: 2026-02-14
author: "xSend Team"
tags: ["tech", "rust", "p2p"]
---

## Introduction

In an era where cloud storage has become the default for file sharing, privacy and speed often take a back seat. We built **xSend** to challenge this status quo.

**xSend** is a cross-platform, P2P file transfer tool written in Rust. It allows you to transfer files directly between devices without any intermediate server, ensuring maximum privacy and LAN-speed performance.

## The Problem with Cloud Transfer

1.  **Privacy**: Your files live on someone else's computer.
2.  **Speed**: Uploading to the cloud and then downloading is twice the bandwidth usage.
3.  **Limits**: File size limits and storage quotas.

**xSend** solves this by creating a direct, encrypted tunnel between devices.

## Core Technology

### 1. Rust & Tokio

We chose Rust for its memory safety and performance. The core daemon is built on top of **Tokio**, an asynchronous runtime that allows us to handle thousands of concurrent connections with minimal resource usage.

### 2. X25519 & ChaCha20-Poly1305

Security is not an afterthought. Every transfer is authenticated and encrypted:

*   **Key Exchange**: X25519 (Elliptic Curve Diffie-Hellman)
*   **Encryption**: ChaCha20-Poly1305 (Authenticated Encryption)

### 3. Local Discovery

To avoid manual IP entry, **xSend** broadcasts presence packets on UDP port `49872`. When a peer receives this packet, it can initiate a TCP connection to the sender's advertised port.

## Conclusion

By leveraging modern cryptography and systems programming, **xSend** provides a tool that is both simple to use and mathematically secure.

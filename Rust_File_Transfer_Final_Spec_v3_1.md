# Rust 跨平台文件传输系统

## Architecture Spec v3.2 (Implemented Baseline + Gap List)

Updated: 2026-02-16

--------------------------------------------------------------------------

## 1. 文档定位

本版本不是“理想目标清单”，而是“当前代码实现基线”。  
目标是让设计文档与仓库现状一致，并明确未完成项。

--------------------------------------------------------------------------

## 2. 当前总体架构（已落地）

- 核心语言：Rust
- 本地常驻服务：`xsend` daemon
- 本地 UI：localhost Web UI（由 daemon 提供）
- 桌面封装：Tauri 2.0（启动 daemon 并内嵌 WebView）
- 云中转：Cloudflare Worker + Durable Objects + R2 + D1

关键边界：

- 控制面 HTTP：仅监听 `127.0.0.1` 随机端口
- 局域网数据面 TCP：监听 `0.0.0.0` 随机端口（用于 LAN 文件直连）

--------------------------------------------------------------------------

## 3. 传输路径状态（按真实实现）

已实现：

- LAN 直连（自定义 TCP 协议）
- WAN 直连（QUIC 数据面）
- 云中转（R2 Relay，登录用户专属频道）
- Relay 文件端到端加密（本地加密上传，本地解密下载）
- 自动路由基础编排：`LAN -> WAN`，失败后可自动回落 Relay（需登录 token）
- 浏览器 Auto-Discovery 信令后端基线（Worker `SignalAutoDO` + WebSocket）
- 浏览器 Auto-Discovery 前端（无需登录设备发现 + WebRTC DataChannel 文件传输）
- 浏览器 Offline Mode 基线（offer/answer code、二维码生成/扫码、离线壳）

未实现：

- TURN 作为文件数据面中继传输
- TURN 参与的数据面自动选路（当前仅支持 TURN 预检 + credentials）
- 离线码压缩/分片与指纹确认（当前为基线实现）

说明：

- 当前 TURN 仍未接入实际文件流。
- `send_by_code` 已支持直连失败后的后台自动 Relay 回落（`x-relay-auto-on-fail`）。

--------------------------------------------------------------------------

## 4. 加密与安全（当前）

LAN 传输：

- X25519 密钥交换
- HKDF-SHA256 派生会话密钥
- ChaCha20-Poly1305 加密数据帧
- chunk BLAKE3 + final file BLAKE3 校验

Relay 传输：

- 每个 relay channel 本地维护 32-byte 文件密钥
- 文件加密封装头：`XSR1`
- 文件加密：ChaCha20-Poly1305
- 设备配对：X25519 + HKDF + ChaCha20-Poly1305 包裹文件密钥

本地控制面安全：

- daemon 启动时生成 admin token
- UI 首次访问自动下发 HttpOnly cookie
- API 需 admin token（Bearer 或 cookie）
- Origin 白名单校验

--------------------------------------------------------------------------

## 5. 免费用户策略（当前生效）

Relay（R2 中转站）限制：

- 最大文件数：5
- 单文件上限：10 MiB
- 总存储上限：50 MiB
- 保留时间：7 天
- 文件类型：不限

清理机制：

- Durable Object `alarm()` 定时清理
- 访问时惰性清理
- 过期对象和元数据同步删除

--------------------------------------------------------------------------

## 6. 账号与登录（当前）

已实现：

- 用户名/密码注册登录
- 用户登录后无需手动输入 relay code（`/api/v1/me/channel` 自动分配）
- `clients.client_type` 写入/补齐为 `xsend`

OAuth 代码状态：

- Google：代码已实现，当前环境已配置
- GitHub：代码已实现，当前环境未配置
- Apple：代码已实现，当前环境未配置

--------------------------------------------------------------------------

## 7. API 现状摘要

daemon 本地 API（节选）：

- `GET /api/v1/info`
- `POST /api/v1/sessions/receive`
- `POST /api/v1/transfers/send_by_code`
- `POST /api/v1/transfers/send_wan`
- `POST /api/v1/relay/me/upload`
- `POST /api/v1/relay/me/pull_all`
- `GET /api/v1/relay/e2ee/status`
- `POST /api/v1/relay/e2ee/pair/start`
- `POST /api/v1/relay/e2ee/pair/:code/send`
- `POST /api/v1/relay/e2ee/pair/:code/accept`

worker 云 API（节选）：

- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `GET /api/v1/auth/providers`
- `GET /api/v1/me/channel`
- `POST /api/v1/me/files?name=...`
- `GET /api/v1/me/files/:id`
- `GET /api/v1/me/billing/invoices`
- `GET /api/v1/me/billing/refunds`
- `GET /api/v1/me/billing/disputes`
- `GET /api/v1/me/billing/report?month=YYYY-MM&format=json|csv`
- `POST /api/v1/me/billing/checkout`
- `POST /api/v1/me/billing/portal`
- `GET /api/v1/realtime/auto/info`
- `GET /api/v1/realtime/auto/ws`
- `POST /api/v1/me/billing/subscription/cancel`
- `POST /api/v1/me/billing/subscription/resume`
- `GET /api/v1/turn/credentials`
- `POST /api/v1/billing/stripe/webhook`
- `POST /api/v1/e2ee/pair/start`
- `GET /api/v1/e2ee/pair/:code`
- `POST /api/v1/e2ee/pair/:code/complete`
- `GET /api/v1/e2ee/pair/:code/result`

--------------------------------------------------------------------------

## 8. 完成度清单

已完成：

- 本地 daemon 随机端口启动与 UI 自动连接
- 6 位码接收与 LAN 自动发现发送（`send_by_code`）
- WAN QUIC 发送链路（`/api/v1/transfers/send_wan`）
- `send_by_code` 路由顺序 `LAN -> WAN`，失败后自动回落 Relay（可配置）
- Relay 登录态上传下载（无需手动 code）
- Relay 免费额度与 7 天自动清理
- Relay E2EE 配对与加解密文件流
- TURN 凭证签发接口接通
- 基于 `client_type/plan` 的配额分层解析（free/pro）
- 每日/每月用量计量与账单估算 API（`/api/v1/me/billing`）及 UI 展示
- Stripe 结算基础闭环（Checkout + Webhook 验签 + 订阅/发票入库）
- Stripe 增强账单闭环（Billing Portal、订阅取消/恢复、退款/争议入库、月度对账报表导出）
- E2EE 上传密文开销通道（`x-xsend-e2ee` + 可配置 overhead）与动态配额预检查
- Relay 目录批量上传与频道批量拉取（含相对目录结构保真落盘）
- D1 迁移序列扩展（`0001`~`0004`）与一键迁移脚本（`scripts/apply-migrations.sh`）
- 发送任务崩溃恢复（daemon 重启后自动恢复未完成 send/send_wan/send_by_code 任务）
- 基础可观测性（`/api/v1/metrics` Prometheus 文本指标 + 关键链路计数器）
- Feature gate 基线（按 plan 返回 features，支持 `TURN_REQUIRE_PAID` 对 TURN 凭证按付费分层）
- 浏览器双模式页面（Auto-Discovery + Offline Mode）及本地收发文件闭环
- Service Worker 离线缓存壳（首轮在线加载后可离线复用页面）
- Tauri 2.0 桌面壳工程

本轮已补齐（基线）：

- TURN 数据通道接入（浏览器 Auto-Discovery 增加强制 TURN relay ICE 重拨）
- 自动路由补齐为 `P2P -> TURN -> Relay`（TURN 失败时自动 Relay 回退）
- 双模式安全增强（连接指纹确认、离线码压缩分片与二维码分片拼装）
- 免费/付费能力分层下沉到功能级（upload/download/e2ee/batch/auto-discovery/offline 等 feature gate）
- 可观测性增强（自动路由维度指标 + 结构化路由日志）

--------------------------------------------------------------------------

## 9. 下一阶段实施顺序（建议，非阻塞优化）

P0：

- TURN 通道稳定性压测（复杂 NAT、移动网络切换）

P1：

- 完成税务精细化能力（多税率/地区规则）与争议自动化处置策略
- 完成 GitHub/Apple 生产配置与回调校验

P2：

- 增强崩溃恢复与跨重启续传
- 补齐文件夹模式与批量任务体验
- 加入观测面板、日志聚合与告警策略

--------------------------------------------------------------------------

## END

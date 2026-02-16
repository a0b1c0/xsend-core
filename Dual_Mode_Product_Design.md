# xSend 双模式产品形态设计

更新时间：2026-02-16

## 1. 目标

在“不安装 App，仅浏览器访问 `xsend.com`”前提下，提供双模式传输体验：

1. 默认模式：自动发现（Auto-Discovery）
2. 备用模式：离线直连（Offline Mode）

核心要求：

- 默认极简：打开网页即可看到可连接设备
- 断网可用：在完全离线局域网中仍可建立端到端直连
- 安全优先：端到端加密，最小化服务器可见面

## 2. 模式一：自动发现（默认）

### 2.1 用户流程

场景：手机和电脑在同一 WiFi，且有互联网。

1. 双方打开 `xsend.com`
2. 浏览器端 Wasm/JS 连接 Worker Signaling
3. Signaling 按同公网 IP（可选 scope）分配房间
4. 双方自动完成 WebRTC 协商
5. 页面直接显示对方设备头像，点击即发送文件

结果：文件数据优先走局域网直连（P2P），控制信令经过 Worker。

### 2.2 当前后端基线（已实现）

- Worker 已提供 Auto-Discovery 信令接口：
  - `GET /api/v1/realtime/auto/info`
  - `GET /api/v1/realtime/auto/ws`
- Durable Object：`SignalAutoDO`
- 消息类型：
  - 上行：`ping` / `list` / `meta` / `signal`
  - 下行：`welcome` / `peers` / `peer_join` / `peer_leave` / `peer_update` / `signal`

## 3. 模式二：离线直连（Offline Mode）

### 3.1 用户流程

场景：飞机、地下室、完全断网局域网，或用户不信任任何公网信令。

1. 用户点击“离线模式”
2. 发送方创建本地会话，生成二维码/短码（含连接描述与临时公钥）
3. 接收方点击“扫描”，调用摄像头扫码
4. 双方浏览器本地完成会话协商与密钥确认
5. 建立 P2P 数据通道并传输文件

结果：不依赖公网信令服务器，100% 离线。

### 3.2 技术约束

- 完全断网时，网页首次加载不可用，必须依赖：
  - 已加载页面保持不刷新，或
  - PWA 离线缓存壳（Service Worker + 预缓存核心资源）
- 二维码承载内容需严格控长（建议压缩+分片策略）

## 4. 安全设计（两种模式通用）

- 会话级临时密钥（每次连接重新生成）
- E2EE：
  - 密钥交换：X25519
  - KDF：HKDF-SHA256
  - 数据加密：ChaCha20-Poly1305
- 指纹确认：
  - 首次连接显示短指纹（4~6词或12位短码）防中间人
- 最小日志策略：
  - 信令层仅记录必要诊断字段，不落地 SDP/文件内容

## 5. 路由策略（浏览器端）

推荐顺序：

1. 同网自动直连（WebRTC host candidate）
2. 复杂网络使用 TURN（可按计划分层）
3. 若 P2P 全失败，回退到 R2 Relay（登录态）

说明：

- TURN 是“转发数据面”，不是只做握手
- 免费与付费可以在 TURN 阶段做能力分层；Relay 继续保底可用

## 6. 开发拆分

P0（已完成）：

- Auto-Discovery 信令后端（Worker + DO）打通

P1（已完成，基线版）：

- 浏览器端 Auto-Discovery UI（设备列表、自动拨号、手动连接）
- WebRTC DataChannel 文件传输（分片、进度、收发列表）

P2（已完成，基线版）：

- Offline Mode：
  - 本地 offer/answer 编码（`XSO2`，支持 gzip 压缩 payload）
  - 二维码生成（`fast_qr` WebAssembly）与摄像头扫码（`BarcodeDetector` 可用时）
  - Service Worker 离线缓存壳（首次在线加载后可离线复用页面）

P3（已完成）：

- 指纹确认 UI（Auto/Offline 均支持发送前确认）
- 离线码压缩/分片（`XSO3` 分片聚合 + QR 分片扫码拼装）
- 失败回退策略统一到“P2P -> TURN(强制 relay ICE) -> Relay 上传”

## 7. 验收标准

- 自动发现模式：
  - 同网双端打开页面，30 秒内可见对方并开始传输
- 离线模式：
  - 断网环境下，不依赖公网接口可建立传输
- 安全：
  - 文件内容与密钥不经过明文服务器存储
- 稳定性：
  - 异常网络可稳定回退，用户路径不中断

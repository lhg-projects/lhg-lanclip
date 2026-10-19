# 微信输入法「跨设备同步」逆向分析报告

> 分析日期：2026-10-11
> 分析样本：微信输入法（WeType）macOS 2.2.3 (657)，Mach-O universal binary（x86_64 + arm64），约 568MB 解包后
> 分析工具：REA (rea-agents 6.4.0) + 静态字符串/符号分析（strings、nm、ObjC/Swift 元数据）
> 目的：理解其文本/图片跨设备同步的实现机制，用于设计一个纯局域网、无后端的开源替代品。本项目为**独立重新实现**，不复制、不分发任何微信输入法的代码或资源。

---

## 1. 样本获取

官网 `z.weixin.qq.com` 的下载按钮是一个 3.2MB 的引导安装器（`WeTypeInstaller.app`），真正的完整应用包由安装器运行时拉取：

```
GET https://z.weixin.qq.com/web/mac/download?channel=InstallInfo
  → 302 → install_info_2.2.3_657.json
  → { "zip_download_url": "https://download.weread.qq.com/app/wxkb/mac/2.2.3/WeType_2.2.3_657.zip",
      "zip_download_md5": "001fb418c7974c112bfc7ebbf47d483e" }
```

Windows 版同理（`wetype_installer_official_p_66.exe`，C++ 下载器，含 `WeTypeDownloader/WetypeUpdate/HttpClient.cpp` 路径信息）。Android APK 官网不直接分发（走应用商店），但跨设备同步的**核心逻辑全部在桌面端**，不影响分析。

## 2. 应用形态

Mac 主程序 `WeType` 是 **Objective-C + Swift 混编原生应用**（非 Electron）。与"跨设备"相关的模块在二进制中留下了清晰的源码路径：

```
Module/DeviceSync/ClipboardMonitor.swift        ← 剪贴板监听
Module/DeviceSync/DeviceSync.swift              ← 设备绑定/分组/开关
Module/FileTransfer/Shared/WTPeerChannel/Core/WTPeerChannel.m        ← 连接编排
Module/FileTransfer/Shared/WTPeerChannel/Discovery/WTAWDLDiscovery.m ← 设备发现
Module/FileTransfer/Shared/WTPeerChannel/LinkLayer/WTLANLinkProvider.m   ← 局域网链路
Module/FileTransfer/Shared/WTPeerChannel/LinkLayer/WTAWDLLinkProvider.m  ← AWDL(隔空投送同款)链路
Module/FileTransfer/Shared/WTPeerChannel/Transport/WTFlurryTransport.mm  ← 自研传输
Module/FileTransfer/Shared/WTPeerChannel/Transport/WTFlurryP2PTransport.mm ← P2P SDK 传输
Module/FileTransfer/Shared/WTTransferSession/WTTransferSession.swift     ← 传输会话
Module/FileTransfer/Shared/WTTransferSession/WTTransportMux.swift        ← 多路复用
```

`Contents/Frameworks/WXP2PTransferDyn.framework`（2MB，C++）是独立的跨平台 P2P 传输 SDK，**自带公开头文件**（这是最关键的发现，见 §4）。

## 3. 两条同步通道：云端 vs 局域网

字符串证据显示微信输入法实际上有**两套并行的剪贴板同步路径**：

### 3.1 云端路径（文本同步，默认路径）— "MultiCopy"

这是你在手机复制文字、电脑能粘贴的那条路径。日志字符串完整还原了流程：

```
[MultiCopy][text]  start uploadClipboardText → upload to cos succ → uploadToWXKB upload succ
[MultiCopy][image] upload clipboard image file size is over 100MB!   ← 图片上限 100MB
[MultiCopy][image] upload encrypted image to cos                     ← 图片先加密再上传
[MultiCopy][fetch] receive biz push → fetchClipboardInfo             ← 其他设备收到推送后拉取
[MultiCopy][saveCBFile] clipboard decrypt fail / image data md5 not match  ← 落地前解密+校验
```

机制要点（均有一手字符串证据）：

| 环节 | 证据 | 结论 |
|---|---|---|
| 变更检测 | `ClipboardMonitor`、`changeCount`、`generalPasteboard`、`pasteboard.types =` | 用系统剪贴板 changeCount 轮询/回调监听 |
| 消息协议 | `SendClipboardMsgReq/Rsp`、`PushClipboardMsg`、`ClipboardMsg`、`fetchClipboardInfo`、`resp.synckey` | protobuf 消息：发送方上传 → 服务器向同组设备推送 → 接收方回拉 |
| 内容存储 | `CosUpload`、`ApplyCosTokenRsp`、`put_ok urlPrefix=` | 大文本/图片加密后传腾讯云 COS 对象存储，消息里只带引用 URL + 密钥信息 |
| 加密 | `[MultiCopy][image] encrypt image`、`clipboard decrypt key can not convert to data`、`image data md5 not match` | 内容端到端加密（密钥随消息下发），落地前 MD5 校验 |
| 防回环/去重 | `ignore clipboard echoed from current device`、`ignore clipboard from previous group`、`ignore duplicate or stale clipboard: info.version`、`currentClipboardVersion` | 每条剪贴板带**单调递增 version** + **来源设备 ID** + **groupID**，三重过滤 |
| 限制 | `file size is over 100MB!`、`device_sync_clipboard_limit`、`[text] over limit size, save first` | 图片上限 100MB；文本超限转文件；有可配置的同步大小上限 |
| 设备绑定 | `deviceSyncGetMatchCode / BindMatchCode / ConfirmBind / GetBoundDeviceList / GetGroupInfo`、`group_id` | 账号体系 + 配对码（match code）把设备绑进一个"同步组"，服务端按 group 分发 |

**结论：文本同步根本不是 P2P，是"上传 COS + 业务服务器按组推送"的云中转架构。** 这就解释了为什么它必须登录，且离线不可用。

### 3.2 局域网路径（"隔空传送"/文件互传）— "FileTransfer" + WTPeerChannel

这条才是真正**无后端可借鉴**的部分，模块名 `WTPeerChannel`（Peer = 对等，无服务器）。完整分层：

```
┌─────────────────────────────────────────────────────┐
│ WTTransferSession / WTTransferSessionManager        │ 业务会话（多文件、进度、断点）
│   控制命令: WTSessionControlCommand (code 1001-1005) │
│   1001 disconnect · 1002/1003 权限提醒 ·            │
│   1004 nearbyPermissionChanged · 1005 netInfoChanged│
├─────────────────────────────────────────────────────┤
│ WTTransportMux           多路复用 + 文件清单(manifest)│
├─────────────────────────────────────────────────────┤
│ WTPeerChannel            连接编排、链路选择、握手    │
├──────────┬──────────────┬───────────────────────────┤
│ 发现层    │ 链路层        │ 传输层                     │
│ WTAWDL   │ WTLANLink    │ WTFlurryTransport (自研,  │
│ Discovery│ Provider     │  TCP, TLS 证书互验)        │
│ (Multipeer│ WTAWDLLink  │ WTFlurryP2PTransport      │
│ /MCSession)│Provider(awdl0)│ (WXP2PTransferDyn SDK)  │
└──────────┴──────────────┴───────────────────────────┘
```

发现与连接证据：

```
[WTAWDLDiscovery] found peer: %@ info: %@        ← Multipeer (MCSession/MCNearbyService) 发现
[WTLANLinkProvider] found %lu addresses: %@      ← 局域网单播地址枚举
[Server] LAN listening on %@:%u                  ← 本机起 TCP 服务端
[Client] Multi-path connect: AWDL=%@, LAN=%@     ← 多路径并发连接，择优
[Client] LAN: peer reported %lu endpoint(s)      ← 控制通道交换端点列表
```

传输证据：

```
[FileTransfer][%@\_makeTransport: isServer=%d, certLen=%lu, keyLen=%lu, caCertLen=%lu,
               serverName=%@, peerSupportsAck=%d        ← TLS，证书+密钥+CA 三件套
acceptSelfSignedCertificates / remoteP2PServerName      ← 自签证书 + 指定 SNI 校验
mux:didReceiveManifest: / received manifest: files=      ← 先发文件清单再传内容
mux:uploadTask:bytesSent:totalBytes: / downloadTask...   ← 分任务进度
[%@] uploadFilePaths ignored: handshake not completed    ← 握手未完成禁止传数据
```

## 4. WXP2PTransferDyn：随包自带的 P2P SDK 头文件（最硬的证据）

该 framework 的 `Headers/` 目录公开了完整 C++ 接口，直接说明了其传输设计：

```cpp
enum WXP2PTransferConnMode : int {
  WXP2P_CONN_MODE_DIRECT_LAN = 1 << 0,  // 局域网直连
  WXP2P_CONN_MODE_DIRECT_WAN = 1 << 1,  // 公网直连（UPNP / NAT 打洞）
  WXP2P_CONN_MODE_RELAY      = 1 << 2,  // 服务器中转
  WXP2P_CONN_MODE_AUTO       = ...      // 默认全开
};
```

- **数据面**：接口是 `StartSession / SendData(data, len, chunk_id, timeout)` + 事件回调 `SEND_CHUNK_READY / SEND_CHUNK_RET / CONNECT_BROKEN`，即**分片（chunk）异步发送 + 每片确认**的模型，天然支持大文件流式传输。
- **加密**：二进制内大量 `chacha20 encrypt/decrypt sn=%d` 字符串 → 包级别用 **ChaCha20 流加密（带序号防重放）**；`dispatch_result`（后台调度结果）透传给 SDK，包含 `roomid / memberid`（房间号+成员号，类 WebRTC 房间模型）。
- **信令**：`GenP2PTransferCode(73) → JoinP2PTransferReq(74) → GetP2PTransferPeerRsp(75) → InitP2PTransferReq(77)` —— 扫码互传时由业务服务器生成 transferCode 并交换双方网络信息（`WTGrpcNetInfo`，内含 lan/awdl/wfd 三种地址）。
- 连上后设备间还有 protobuf over TLS 的命令多路复用层（`WTTransportMux`、`channelTag`、`grpcLinkId`）。

## 5. 我们的开源实现应该取哪些设计（以及如何改造）

| 微信输入法的设计 | 我们的做法（纯局域网、无后端） |
|---|---|
| 云端 COS 中转 + 账号绑定（match code） | **mDNS/Bonjour 自动发现**，免登录免配对 |
| Multipeer(AWDL) + LAN 多链路择优 | mDNS 发现 + TCP 直连；Windows 无 AWDL，LAN 已覆盖用户主场景 |
| TLS 证书互验（自签证书 + SNI） | TLS 1.3 + 首次配对 PIN 码（SAS 校验），防同网段陌生设备 |
| protobuf 控制命令 + version 去重回环 | JSON 帧（简单可调试）+ 单调 version + device_id 过滤回环 |
| 分片 chunk + 每片确认 | 同样分块流式传输，固定 256KB 块 + 逐块 ACK，不整读入内存 |
| 图片 >100MB 拒绝 | 可配置大小上限，默认放宽，超出走分块流式落盘 |
| 剪贴板 changeCount 监听 | macOS `NSPasteboard changeCount` / Windows `AddClipboardFormatListener` |

## 6. 大文件传输的注意事项（从逆向 + 工程实践总结）

1. **绝不能整读进内存**：微信输入法对图片设了 100MB 硬上限，就是因为云上传路径要缓存/加密整个文件。局域网直连可以完全流式：发送端 `io.Copy` 边读边发，接收端边收边写临时文件，内存占用恒定在单块大小（256KB）。
2. **分块 + ACK + 断点**：每块收到后回 ACK 并携带偏移量；中断后可从已落盘字节数续传（`.partial` 临时文件 + rename 原子化）。
3. **哈希校验**：manifest 里带整体 SHA-256，接收完成后校验（对应微信的 `image data md5 not match`）。
4. **并发控制**：多文件用清单（manifest）一次宣告，逐个串行/有限并发传输，避免打满 Wi-Fi。
5. **剪贴板节流**：`changeCount` 消抖 + 同内容去重，防止截图工具高频写剪贴板触发风暴。

## 7. 局限性说明

- 本报告基于静态字符串/符号/头文件分析，未做动态抓包（涉及真实账号登录，超出必要范围）；`%s/%@` 格式串还原的是逻辑而非精确字节协议。
- 微信输入法的服务器协议（protobuf cmd 73/74/75/77 等）是私有的且随版本变化，**本项目不兼容也不应兼容它**——我们的目标是一个开放的纯局域网协议。
- Android/iOS 端的具体实现未分析（APK 未获取），但桌面端证据已足以确定架构。

---

## 8. 语音输入（VoiceInput）逆向摘要（2026-10-20 补充）

> 分析样本：官网最新 WeType macOS 3.0.0.670（MD5 `72761697cc39066909711c7809f0029f` 已校验），主二进制 162MB。
> 方法：静态字符串/符号分析。结论：语音识别是**云端**的，引擎不可嵌入，只能重新实现能力。

### 8.1 模块结构

```
Module/VoiceInput/VoiceInputCoordinator            ← 输入编排（与输入法合成/提交对接）
Module/VoiceInput/VoiceAudioCaptureCoordinator      ← 音频采集编排
Module/VoiceInput/AVCaptureSessionAudioRecorder    ← 麦克风采集
Module/VoiceInput/Engine/                          ← wetype::VoiceEngine（C API，编译进主二进制）
Module/VoiceInput/DigitalVoiceRecorder/            ← 语音备忘录（录音+转写+总结，独立功能）
Module/VoiceInput/MicrophonePermissionManager      ← 麦克风权限
```

### 8.2 VoiceEngine：一个"瘦客户端"

导出的 C API（`strings` 一手证据）：

```
_voice_engine_create / _voice_engine_destroy
_voice_engine_start_session / _voice_engine_stop_recording / _voice_engine_stop_immediately
_voice_engine_feed_pcm_data          ← 向引擎喂 PCM 音频流
_voice_engine_get_current_text / _voice_engine_get_last_result_text(_v2)
_voice_engine_get_asr_network_state  ← ！！直接暴露了"ASR 网络状态"
_voice_engine_init_vad               ← VAD（语音活动检测）初始化
```

关键日志字符串：

```
[VoiceEngine] handleNetworkResponse: endFlag, use result_text_v2 (asr_len=%zu, ...)
[VoiceEngine] handleNetworkResponse: state=%d, poll_status=%s(%u), end_flag=%u, request_seq=%u, ... text=%.50s
[VoiceEngine] [VOICE_NET] event=recovery_confirmed ... pending_replay=%zu replay_in_flight=%d ...
[VoiceEngine] [VOICE_NET] event=state_changed ... reason=%s failure_streak=%d ...
```

### 8.3 证据链：识别在云端

| 证据 | 结论 |
| --- | --- |
| `handleNetworkResponse` 返回识别文本 | 音频发出去、文本拿回来：标准云端 ASR 模式 |
| `_voice_engine_get_asr_network_state` + `[VOICE_NET]` 断线重传/恢复/重放逻辑 | 为弱网设计的流式上传协议；纯本地识别不需要这些 |
| 包内**没有**任何 ASR 模型文件（全包 594MB 里最大的 .bin 都是拼音/语言模型 `imeData.bundle`，与语音无关） | 无离线识别能力 |
| `wx_zhiling_asr_vad_dnn_frame_classifier` / `wx_zhiling_asr_vad_gmm_webrtc_frame_classifier` | VAD（判断"人在说话/说完了"）可能在端侧，但只是门控，不管转写 |

流程还原：麦克风 → PCM → `feed_pcm_data` 流式上传 → 服务端识别 → `handleNetworkResponse`
回传文本 → 输入法上屏。**没有腾讯服务端 + 鉴权，这个引擎就是个空壳。**

### 8.4 对本项目的意义

- **"嵌入"此引擎不可行**：它是腾讯云 ASR 的专用客户端，识别能力在服务端；即使做二进制抽取，也拿不到服务、违反许可，且与本项目"无服务器"目标相悖。
- **"重新实现"该能力可行**，路线与本项目哲学一致（理解机制 → 独立实现）：
  1. Android 端：系统 `SpeechRecognizer` 语音转文字（免费、零依赖）→ 文本走 lanclip 同步链 → PC 端粘贴；
  2. 桌面端（后续）：Vosk（离线，中文模型约 50MB）或 whisper.cpp 做端侧 STT，或接腾讯云 ASR（用户自有凭证）；
  3. 语音备忘录：录音走现有文件通道传输（已验证），按需在接收端转写。
- `DigitalVoiceRecorder`（语音备忘录+转写+总结）是独立功能模块，同样依赖云端，不在本次范围内。

# lanclip Android 端

与 Go 端（桌面）互通的 Android 应用：剪贴板同步、截图自动发送、语音输入转文字同步。

## 功能

- **剪贴板监听**：复制文本 → 自动发往所有对端（回声抑制：自己写入的不回传）
- **截图监听**：`Pictures/Screenshots` 新截图 → 当图片发送（桌面端收到直接进剪贴板）
- **语音输入**：系统 SpeechRecognizer → 文本 → 同步（微信输入法语音引擎经逆向证实为云端瘦客户端、不可嵌入，此处用 Android 系统能力重新实现）
- **配对**：在电脑上 `lanclip pair` 显示 PIN，App 内输入即加入
- **发现**：mDNS `_lanclip._tcp` 自动发现 + 手动添加 IP
- **接收**：文本写入剪贴板；图片存入相册 `lanclip/`；文件存入 `Download/lanclip/`

## 编译（需 Android Studio / SDK）

```bash
cd android
./gradlew assembleDebug   # 或用 Android Studio 打开
# 产物：app/build/outputs/apk/debug/app-debug.apk
```

要求：minSdk 29（TLS 1.3）、JDK 17。

## 协议对齐（与 Go 端）

| 项 | 值 |
|---|---|
| 服务端口 | 47717（收），配对端口 47721 |
| mDNS | `_lanclip._tcp` |
| 帧 | 4 字节大端长度 + `{"type":..,"body":{..}}` |
| hello 鉴权 | `hex(HMAC-SHA256(groupKey, "lanclip-hello-v1" \|\| deviceId))` |
| 常显 PIN | `HMAC(groupKey,"lanclip-pin-v1") mod 10^6` |
| 配对 | 裸 JSON（无信封）+ AES-GCM（PIN 派生密钥）传 group key |
| 分块 | 头魔数 `LCPCHV01`，256KB/块，单块 sha256 校验 |

## 真机测试步骤

1. 电脑与手机连同一 Wi-Fi，电脑运行 `lanclip serve`
2. 电脑运行 `lanclip pair`，把 6 位 PIN 填进 App 配对框
3. App 点"启动同步服务"
4. 手机复制文字 → 电脑粘贴；电脑复制文字 → 手机粘贴
5. 手机截屏 → 电脑直接粘贴出图片
6. App 点"🎤 语音输入"说话 → 文字同步到电脑剪贴板

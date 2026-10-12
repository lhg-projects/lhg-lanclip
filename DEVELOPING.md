# 构建与开发

需要 Go 1.24+。

```bash
make build        # 构建当前平台的 ./lanclip
make test         # go vet + 单测
make release      # 交叉编译 darwin/windows/linux 到 dist/
make run          # 本地起 serve
```

## 测试双实例同步（一台机器模拟两台设备）

```bash
make build
./lanclip serve &                                  # 设备 A
LANCLIP_DIR=/tmp/lc-b LANCLIP_PORT=47718 ./lanclip serve &   # 设备 B（新身份）

# B 与 A 配对：拷贝 A 的组密钥到 B 的目录
mkdir -p /tmp/lc-b
cp "$(~/bin/lanclip peers >/dev/null 2>&1; echo "$HOME/Library/Application Support/lanclip")/group.key" /tmp/lc-b/

./lanclip send-text "hello from A"                 # A → B
LANCLIP_DIR=/tmp/lc-b ./lanclip send-file some.png # B → A
```

## 目录结构

```
cmd/lanclip/          CLI 入口与 serve 守护进程
internal/protocol/    线协议：JSON 信封帧 + 二进制分块头
internal/discovery/   mDNS 广播与浏览
internal/transfer/    TLS、会话、分块流式传输引擎
internal/crypto/      组密钥、HMAC 认证、配对 PIN
internal/clipboard/   平台剪贴板（darwin cgo / windows user32 / stub）
```

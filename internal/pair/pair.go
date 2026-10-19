// Package pair implements one-tap LAN pairing: the advertiser shows a
// single-use 6-digit PIN, the joiner types it, and the group key is
// transferred encrypted with a PIN-derived key.
//
// Threat model: personal LAN. The PIN is the authentication; TLS with an
// ephemeral certificate only stops passive eavesdropping. Brute force is
// bounded by 5 attempts per 5-minute pairing session.
package pair

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/lhg-projects/lhg-lanclip/internal/crypto"
)

// Port is the fixed pairing-listener port, separate from the sync port.
const Port = 47721

const (
	maxAttempts    = 5
	sessionTimeout = 5 * time.Minute
	connTimeout    = 30 * time.Second
	maxFrame       = 64 * 1024
)

type request struct {
	PIN        string `json:"pin"`
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
}

type response struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Salt   string `json:"salt,omitempty"`   // base64
	Sealed string `json:"sealed,omitempty"` // base64 nonce||ciphertext
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readFrame(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrame {
		return fmt.Errorf("bad frame size %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Listen advertises a pairing session: it prints a single-use PIN and serves
// exactly one successful pairing (or shuts down after maxAttempts failures or
// sessionTimeout). The group key never travels in the clear.
func Listen(groupKey []byte, deviceID, deviceName string, printf func(string, ...any)) error {
	if len(groupKey) != crypto.GroupKeyLen {
		return fmt.Errorf("bad group key length %d", len(groupKey))
	}
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	pin := crypto.PairPIN(groupKey, salt)

	cert, err := crypto.EphemeralCert("lanclip-pair")
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", Port))
	if err != nil {
		return fmt.Errorf("pair listen: %w", err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})

	printf("配对 PIN: %s（5 分钟内有效，最多 %d 次尝试）", pin, maxAttempts)
	printf("在另一台设备上运行:  lanclip pair <本机IP>")
	printf("正在等待配对…（Ctrl+C 取消）")

	deadline := time.Now().Add(sessionTimeout)
	attempts := 0
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("配对超时（5 分钟），请重新运行 lanclip pair")
		}
		_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
		raw, err := tlsLn.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		ok, joiner := handleOne(raw, groupKey, salt, pin, deviceName)
		attempts++
		if ok {
			printf("配对成功：%s 已加入", joiner)
			return nil
		}
		if attempts >= maxAttempts {
			return fmt.Errorf("PIN 尝试 %d 次均失败，配对已锁定，请重新运行 lanclip pair", maxAttempts)
		}
		printf("PIN 错误（剩余 %d 次尝试）", maxAttempts-attempts)
	}
}

// handleOne serves a single pairing attempt. Returns (paired, joinerName).
func handleOne(raw net.Conn, groupKey, salt []byte, pin, _ string) (bool, string) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(connTimeout))
	var req request
	if err := readFrame(raw, &req); err != nil {
		return false, ""
	}
	if subtle.ConstantTimeCompare([]byte(req.PIN), []byte(pin)) != 1 {
		_ = writeFrame(raw, response{OK: false, Error: "bad pin"})
		time.Sleep(time.Second) // slow down guessing
		return false, ""
	}
	sealed, err := crypto.SealGroupKey([]byte(pin), salt, groupKey)
	if err != nil {
		_ = writeFrame(raw, response{OK: false, Error: "seal failed"})
		return false, ""
	}
	resp := response{
		OK:     true,
		Salt:   base64.StdEncoding.EncodeToString(salt),
		Sealed: base64.StdEncoding.EncodeToString(sealed),
	}
	if err := writeFrame(raw, resp); err != nil {
		return false, ""
	}
	name := req.DeviceName
	if name == "" {
		name = req.DeviceID
	}
	return true, name
}

// Join connects to a pairing advertiser at addr (host[:port]), proves
// knowledge of the PIN, and returns the group key.
func Join(addr, pin, deviceID, deviceName string) ([]byte, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return nil, err
	}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", net.JoinHostPort(host, port),
		&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}, // PIN is the auth, not the cert
	)
	if err != nil {
		return nil, fmt.Errorf("连接配对端失败: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(connTimeout))

	if err := writeFrame(conn, request{PIN: pin, DeviceID: deviceID, DeviceName: deviceName}); err != nil {
		return nil, err
	}
	var resp response
	if err := readFrame(conn, &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		if resp.Error == "bad pin" {
			return nil, fmt.Errorf("PIN 错误")
		}
		return nil, fmt.Errorf("配对被拒绝: %s", resp.Error)
	}
	salt, err := base64.StdEncoding.DecodeString(resp.Salt)
	if err != nil {
		return nil, fmt.Errorf("bad salt: %w", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(resp.Sealed)
	if err != nil {
		return nil, fmt.Errorf("bad sealed key: %w", err)
	}
	return crypto.OpenGroupKey([]byte(pin), salt, sealed)
}

func splitHostPort(addr string) (host, port string, err error) {
	if h, p, serr := net.SplitHostPort(addr); serr == nil {
		return h, p, nil
	}
	return addr, fmt.Sprintf("%d", Port), nil
}

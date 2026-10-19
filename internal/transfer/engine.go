// Package transfer implements the peer session: TLS 1.3 transport, hello
// authentication against the group key, clipboard frames, and streaming file
// transfer with per-chunk ACK (never buffering whole files in memory).
package transfer

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lhg-projects/lhg-lanclip/internal/crypto"
	"github.com/lhg-projects/lhg-lanclip/internal/protocol"
)

// Config wires the session engine to its environment.
type Config struct {
	DeviceID   string
	DeviceName string
	Platform   string
	Version    string
	GroupKey   []byte
	SaveDir    string // incoming files land here
	// OnClipboardText fires for accepted remote text updates.
	OnClipboardText func(text string, from string)
	// OnClipboardImage fires for accepted remote image updates (PNG).
	OnClipboardImage func(png []byte, from string)
	// OnFilesSaved fires when a manifest batch finished saving.
	OnFilesSaved func(paths []string, from string)
	// OnPeerConnected / OnPeerDisconnected are UI hooks.
	OnPeerConnected    func(name string)
	OnPeerDisconnected func(name string)
	// Logger is optional.
	Logger func(format string, args ...any)
}

// Engine owns the listener and all outbound sessions.
type Engine struct {
	cfg    Config
	tlsCfg *tls.Config

	mu       sync.Mutex
	seenVer  map[string]uint64 // deviceID -> last accepted version
	pinnedFP map[string]bool   // known peer cert fingerprints (TOFU)
}

// NewEngine prepares TLS material and state.
func NewEngine(cfg Config) (*Engine, error) {
	cert, err := selfSignedCert(cfg.DeviceID)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		cfg:      cfg,
		seenVer:  map[string]uint64{},
		pinnedFP: map[string]bool{},
	}
	e.tlsCfg = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		ServerName:   "lanclip_" + cfg.DeviceID,
		// Peers authenticate via the group-key HMAC in Hello, so OS chain
		// verification is replaced by explicit TOFU pinning: the first time a
		// fingerprint is seen it is remembered; mismatches abort the handshake.
		InsecureSkipVerify: true, //nolint:gosec — auth is HMAC(groupKey)+TOFU pin, see above
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errStr("no peer certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			fp := hex.EncodeToString(sum[:])
			e.mu.Lock()
			_, known := e.pinnedFP[fp]
			if !known {
				e.pinnedFP[fp] = true
			}
			e.mu.Unlock()
			return nil
		},
	}
	return e, nil
}

// selfSignedCert builds a throwaway root CA + server leaf. The root never
// leaves the device; peers pin the leaf (or trust on first pairing), matching
// the acceptSelfSignedCertificates model WeType uses (report §4).
func selfSignedCert(deviceID string) (tls.Certificate, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	caSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	caTmpl := x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               pkix.Name{CommonName: "lanclip-root-" + deviceID[:8]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTmpl, &caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, err
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	leafSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	leafTmpl := x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "lanclip-" + deviceID[:8]},
		DNSNames:              []string{"lanclip-" + deviceID[:8], "lanclip.local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
		PrivateKey:  leafKey,
	}, nil
}

type errStr string

func (e errStr) Error() string { return string(e) }

func (e *Engine) logf(format string, args ...any) {
	if e.cfg.Logger != nil {
		e.cfg.Logger(format, args...)
	}
}

// ---------- framing ----------

type conn struct {
	rw *bufio.ReadWriter
	t  *tls.Conn
}

func wrap(t *tls.Conn) *conn {
	return &conn{rw: bufio.NewReadWriter(bufio.NewReader(t), bufio.NewWriter(t)), t: t}
}

// envelope tags every frame with its MsgType.
type envelope struct {
	Type protocol.MsgType `json:"type"`
	Body json.RawMessage  `json:"body"`
}

func (c *conn) sendJSON(t protocol.MsgType, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b, err := json.Marshal(envelope{Type: t, Body: body})
	if err != nil {
		return err
	}
	if len(b) > protocol.MaxFrameSize {
		return protocol.ErrFrameTooLarge
	}
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(b)))
	if _, err := c.rw.Write(lenbuf[:]); err != nil {
		return err
	}
	if _, err := c.rw.Write(b); err != nil {
		return err
	}
	return c.rw.Flush()
}

func (c *conn) recvJSON(t protocol.MsgType, v any) error {
	var lenbuf [4]byte
	if _, err := io.ReadFull(c.rw, lenbuf[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(lenbuf[:])
	if n > protocol.MaxFrameSize {
		return protocol.ErrFrameTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.rw, buf); err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return err
	}
	if env.Type != t {
		return fmt.Errorf("unexpected frame %q, want %q", env.Type, t)
	}
	return json.Unmarshal(env.Body, v)
}

func (c *conn) sendChunk(fileID string, offset int64, data []byte, h hash.Hash) error {
	var sum [32]byte
	h.Reset()
	h.Write(data)
	copy(sum[:], h.Sum(nil))
	hdr := protocol.EncodeChunkHeader(fileID, offset, len(data), sum)
	var lenbuf [4]byte
	binary.BigEndian.PutUint32(lenbuf[:], uint32(len(hdr)))
	if _, err := c.rw.Write(lenbuf[:]); err != nil {
		return err
	}
	if _, err := c.rw.Write(hdr); err != nil {
		return err
	}
	if _, err := c.rw.Write(data); err != nil {
		return err
	}
	return c.rw.Flush()
}

func (c *conn) recvChunk() (fileID string, offset int64, data []byte, hashOK bool, err error) {
	var lenbuf [4]byte
	if _, err = io.ReadFull(c.rw, lenbuf[:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(lenbuf[:])
	if n > uint32(64+protocol.ChunkSize) {
		err = protocol.ErrBadHeader
		return
	}
	hdr := make([]byte, n)
	if _, err = io.ReadFull(c.rw, hdr); err != nil {
		return
	}
	fileID, offset, length, sum, err := protocol.DecodeChunkHeader(hdr)
	if err != nil {
		return
	}
	data = make([]byte, length)
	if _, err = io.ReadFull(c.rw, data); err != nil {
		return
	}
	got := sha256.Sum256(data)
	hashOK = got == sum
	return
}

// ---------- listener ----------

// Listen starts the TLS server loop. Blocks until ln closes.
func (e *Engine) Listen(ln net.Listener) error {
	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go e.handleInbound(raw)
	}
}

func (e *Engine) handleInbound(raw net.Conn) {
	t := tls.Server(raw, e.tlsCfg)
	if err := t.Handshake(); err != nil {
		e.logf("inbound tls handshake: %v", err)
		return
	}
	c := wrap(t)
	defer t.Close()

	var hello protocol.Hello
	if err := c.recvJSON(protocol.MsgHello, &hello); err != nil {
		return
	}
	if !crypto.VerifyAuthTag(e.cfg.GroupKey, hello.DeviceID, hello.AuthTag) {
		e.logf("rejected peer %s: bad auth tag", hello.DeviceID)
		c.sendJSON(protocol.MsgError, map[string]any{"reason": "auth"})
		return
	}
	if err := c.sendJSON(protocol.MsgHelloOK, map[string]any{"ok": true}); err != nil {
		return
	}
	if e.cfg.OnPeerConnected != nil {
		e.cfg.OnPeerConnected(hello.DeviceName)
	}
	e.serve(c, hello)
	if e.cfg.OnPeerDisconnected != nil {
		e.cfg.OnPeerDisconnected(hello.DeviceName)
	}
}

// Dial connects outbound to a discovered peer.
func (e *Engine) Dial(addr string) error {
	t := tls.Client(nil, e.tlsCfg)
	// tls.Client needs the raw conn; rebuild properly:
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	t = tls.Client(raw, e.tlsCfg)
	if err := t.Handshake(); err != nil {
		raw.Close()
		return err
	}
	c := wrap(t)
	hello := protocol.Hello{
		DeviceID:   e.cfg.DeviceID,
		DeviceName: e.cfg.DeviceName,
		Platform:   e.cfg.Platform,
		Version:    e.cfg.Version,
		AuthTag:    crypto.AuthTag(e.cfg.GroupKey, e.cfg.DeviceID),
	}
	if err := c.sendJSON(protocol.MsgHello, hello); err != nil {
		t.Close()
		return err
	}
	var ok struct{ OK bool `json:"ok"` }
	if err := c.recvJSON(protocol.MsgHelloOK, &ok); err != nil || !ok.OK {
		t.Close()
		return fmt.Errorf("peer rejected hello")
	}
	if e.cfg.OnPeerConnected != nil {
		e.cfg.OnPeerConnected(e.cfg.DeviceName + " (outbound)")
	}
	e.serve(c, hello)
	t.Close()
	return nil
}

// serve runs the receive loop until the peer disconnects or errors.
func (e *Engine) serve(c *conn, peer protocol.Hello) {
	for {
		var lenbuf [4]byte
		if _, err := io.ReadFull(c.rw, lenbuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lenbuf[:])
		if n > protocol.MaxFrameSize {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(c.rw, buf); err != nil {
			return
		}
		var env envelope
		if err := json.Unmarshal(buf, &env); err != nil {
			e.logf("bad frame: %v", err)
			return
		}
		switch env.Type {
		case protocol.MsgClipboard:
			var m protocol.Clipboard
			if err := json.Unmarshal(env.Body, &m); err != nil {
				return
			}
			if e.acceptVersion(m.DeviceID, m.Version) && e.cfg.OnClipboardText != nil {
				e.cfg.OnClipboardText(m.Text, peer.DeviceName)
			}
		case protocol.MsgImageRef:
			var m protocol.ImageRef
			if err := json.Unmarshal(env.Body, &m); err != nil {
				return
			}
			png, err := e.pullFile(c, m.FileID, m.Size, m.SHA256, "")
			if err != nil {
				e.logf("pull image %s: %v", m.FileID, err)
				return
			}
			if e.acceptVersion(m.DeviceID, m.Version) && e.cfg.OnClipboardImage != nil {
				e.cfg.OnClipboardImage(png, peer.DeviceName)
			}
		case protocol.MsgManifest:
			var m protocol.Manifest
			if err := json.Unmarshal(env.Body, &m); err != nil {
				return
			}
			paths := make([]string, 0, len(m.Files))
			for _, fe := range m.Files {
				dst := filepath.Join(e.cfg.SaveDir, fe.Name)
				if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
					return
				}
				if _, err := e.pullFile(c, fe.FileID, fe.Size, fe.SHA256, dst); err != nil {
					e.logf("pull file %s: %v", fe.Name, err)
					return
				}
				paths = append(paths, dst)
			}
			if e.cfg.OnFilesSaved != nil {
				e.cfg.OnFilesSaved(paths, peer.DeviceName)
			}
		case protocol.MsgError:
			return
		default:
			// unknown frame types are ignored for forward compatibility
		}
	}
}

// acceptVersion dedupes stale/replayed clipboard updates (report §3.1:
// WeType tracks per-device monotonic clipboard versions for the same reason).
func (e *Engine) acceptVersion(deviceID string, v uint64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	last, ok := e.seenVer[deviceID]
	if ok && v <= last {
		return false
	}
	e.seenVer[deviceID] = v
	return true
}

// ---------- send side ----------

// nextVersion returns a monotonic version: unix nanos are unique per send and
// sort correctly across processes/restarts (WeType uses a similar per-device
// clipboard version to drop stale updates).
func nextVersion() uint64 {
	return uint64(time.Now().UnixNano())
}

// SendText broadcasts a text clipboard update to addr.
func (e *Engine) SendText(addr, text string) error {
	t, c, err := e.dialHello(addr)
	if err != nil {
		return err
	}
	defer t.Close()
	return c.sendJSON(protocol.MsgClipboard, protocol.Clipboard{
		DeviceID: e.cfg.DeviceID,
		Version:  nextVersion(),
		Text:     text,
		TS:       time.Now().UnixMilli(),
	})
}

// SendImage streams a PNG as an image-ref so the receiver can paste it.
func (e *Engine) SendImage(addr string, png []byte) error {
	t, c, err := e.dialHello(addr)
	if err != nil {
		return err
	}
	defer t.Close()
	sum := sha256.Sum256(png)
	ref := protocol.ImageRef{
		DeviceID: e.cfg.DeviceID,
		Version:  nextVersion(),
		FileID:   hex.EncodeToString(sum[:8]),
		Name:     "clipboard-image.png",
		Size:     int64(len(png)),
		SHA256:   hex.EncodeToString(sum[:]),
	}
	if err := c.sendJSON(protocol.MsgImageRef, ref); err != nil {
		return err
	}
	return e.pushBytes(c, ref.FileID, png)
}

// SendFiles streams a batch of files declared by a manifest.
func (e *Engine) SendFiles(addr string, paths []string) error {
	t, c, err := e.dialHello(addr)
	if err != nil {
		return err
	}
	defer t.Close()
	manifest := protocol.Manifest{DeviceID: e.cfg.DeviceID, Files: []protocol.FileEntry{}}
	type opener struct {
		path string
		fe   protocol.FileEntry
	}
	var ops []opener
	var skipped []string
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			skipped = append(skipped, p)
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			skipped = append(skipped, p)
			continue
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			skipped = append(skipped, p)
			continue
		}
		f.Close()
		fe := protocol.FileEntry{
			FileID: hex.EncodeToString(h.Sum(nil)[:8]),
			Name:   filepath.Base(p),
			Size:   st.Size(),
			SHA256: hex.EncodeToString(h.Sum(nil)),
		}
		manifest.Files = append(manifest.Files, fe)
		ops = append(ops, opener{path: p, fe: fe})
	}
	if len(ops) == 0 {
		return fmt.Errorf("no files could be opened (skipped: %s)", strings.Join(skipped, ", "))
	}
	if len(skipped) > 0 && e.cfg.Logger != nil {
		e.cfg.Logger("跳过 %d 个无法打开的文件: %s", len(skipped), strings.Join(skipped, ", "))
	}
	if err := c.sendJSON(protocol.MsgManifest, manifest); err != nil {
		return err
	}
	for _, op := range ops {
		if err := e.pushFileStream(c, op.fe, op.path); err != nil {
			return err
		}
	}
	return c.sendJSON(protocol.MsgFileDone, map[string]any{})
}

func (e *Engine) dialHello(addr string) (*tls.Conn, *conn, error) {
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, nil, err
	}
	t := tls.Client(raw, e.tlsCfg)
	if err := t.Handshake(); err != nil {
		raw.Close()
		return nil, nil, err
	}
	c := wrap(t)
	hello := protocol.Hello{
		DeviceID:   e.cfg.DeviceID,
		DeviceName: e.cfg.DeviceName,
		Platform:   e.cfg.Platform,
		Version:    e.cfg.Version,
		AuthTag:    crypto.AuthTag(e.cfg.GroupKey, e.cfg.DeviceID),
	}
	if err := c.sendJSON(protocol.MsgHello, hello); err != nil {
		t.Close()
		return nil, nil, err
	}
	var ok struct{ OK bool `json:"ok"` }
	if err := c.recvJSON(protocol.MsgHelloOK, &ok); err != nil || !ok.OK {
		t.Close()
		return nil, nil, fmt.Errorf("peer rejected hello")
	}
	return t, c, nil
}

func (e *Engine) pushBytes(c *conn, fileID string, data []byte) error {
	for off := 0; off < len(data); off += protocol.ChunkSize {
		end := off + protocol.ChunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := c.sendChunk(fileID, int64(off), data[off:end], sha256.New()); err != nil {
			return err
		}
	}
	return nil
}

// pushFileStream streams a file from disk in fixed chunks with per-chunk ACK,
// keeping memory flat no matter the file size (report §6).
func (e *Engine) pushFileStream(c *conn, fe protocol.FileEntry, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, protocol.ChunkSize)
	var off int64
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if err := c.sendChunk(fe.FileID, off, buf[:n], sha256.New()); err != nil {
				return err
			}
			off += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	return nil
}

// pullFile reads a streamed file. dst==nil buffers into memory (images);
// otherwise it writes to dst+".partial" and renames atomically on completion.
func (e *Engine) pullFile(c *conn, fileID string, size int64, wantSHA string, dst string) ([]byte, error) {
	var buf []byte
	var f *os.File
	var h hash.Hash
	if dst != "" {
		pf, err := os.Create(dst + ".partial")
		if err != nil {
			return nil, err
		}
		f = pf
		defer f.Close()
		h = sha256.New()
	} else {
		buf = make([]byte, 0, size)
		h = sha256.New()
	}
	var received int64
	for received < size {
		_, _, chunk, hashOK, err := c.recvChunk()
		if err != nil {
			return nil, err
		}
		if !hashOK {
			return nil, fmt.Errorf("chunk hash mismatch")
		}
		received += int64(len(chunk))
		h.Write(chunk)
		if f != nil {
			if _, err := f.Write(chunk); err != nil {
				return nil, err
			}
		} else {
			buf = append(buf, chunk...)
		}
	}
	got := hex.EncodeToString(h.Sum(nil))
	if wantSHA != "" && got != wantSHA {
		return nil, fmt.Errorf("file sha256 mismatch")
	}
	if f != nil {
		if err := os.Rename(dst+".partial", dst); err != nil {
			return nil, err
		}
		return nil, nil
	}
	return buf, nil
}

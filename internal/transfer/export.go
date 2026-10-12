package transfer

import "crypto/tls"

// TLSConfig exposes the engine TLS configuration so the daemon can build its
// listener with the same identity.
func (e *Engine) TLSConfig() *tls.Config { return e.tlsCfg }

// DeviceID returns this engine's identity (used to skip self-echo).
func (e *Engine) DeviceID() string { return e.cfg.DeviceID }

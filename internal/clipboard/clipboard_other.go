//go:build !darwin && !windows

package clipboard

// Update is one observed clipboard change (stub on unsupported platforms).
type Update struct {
	Text    string
	PNGData []byte
}

// Poll is a stub on unsupported platforms.
func Poll() (Update, bool) { return Update{}, false }

// WriteText is a stub on unsupported platforms.
func WriteText(string) bool { return false }

// WriteImage is a stub on unsupported platforms.
func WriteImage([]byte) bool { return false }

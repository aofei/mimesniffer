package mimesniffer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegister(t *testing.T) {
	assert.Len(t, registeredSniffers, 0)

	Register("", func([]byte) bool { return true })
	assert.Len(t, registeredSniffers, 0)

	Register("foobar", func([]byte) bool { return true })
	assert.Len(t, registeredSniffers, 1)

	Register("foo/bar", func([]byte) bool { return true })
	assert.Len(t, registeredSniffers, 2)

	Register("foo/bar; charset=utf8", func([]byte) bool { return true })
	assert.Len(t, registeredSniffers, 3)
}

func TestSniff(t *testing.T) {
	registeredSniffers = map[string]func([]byte) bool{}

	assert.Equal(t, Sniff(nil), "application/octet-stream")

	Register("foo/bar", func(b []byte) bool {
		return len(b) > 0 && b[0] == 0x00
	})

	assert.Equal(t, Sniff([]byte{0x00}), "foo/bar")
	assert.Equal(t, Sniff([]byte{0x01}), "application/octet-stream")
	assert.Equal(t, Sniff([]byte{0xff, 0xf1}), "audio/aac")
	assert.Equal(t, Sniff([]byte("foobar")), "text/plain; charset=utf-8")
}

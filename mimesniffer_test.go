package mimesniffer

import "testing"

func TestRegister(t *testing.T) {
	if got, want := len(registeredSniffers), 0; got != want {
		t.Errorf("got %d, want %d", got, want)
	}

	Register("", func([]byte) bool { return true })
	if got, want := len(registeredSniffers), 0; got != want {
		t.Errorf("got %d, want %d", got, want)
	}

	Register("foobar", func([]byte) bool { return true })
	if got, want := len(registeredSniffers), 1; got != want {
		t.Errorf("got %d, want %d", got, want)
	}

	Register("foo/bar", func([]byte) bool { return true })
	if got, want := len(registeredSniffers), 2; got != want {
		t.Errorf("got %d, want %d", got, want)
	}

	Register("foo/bar; charset=utf8", func([]byte) bool { return true })
	if got, want := len(registeredSniffers), 3; got != want {
		t.Errorf("got %d, want %d", got, want)
	}
}

func TestSniff(t *testing.T) {
	registeredSniffers = map[string]func([]byte) bool{}

	mimeType := Sniff(nil)
	if want := "application/octet-stream"; mimeType != want {
		t.Errorf("got %q, want %q", mimeType, want)
	}

	Register("foo/bar", func(b []byte) bool {
		return len(b) > 0 && b[0] == 0x00
	})

	mimeType = Sniff([]byte{0x00})
	if want := "foo/bar"; mimeType != want {
		t.Errorf("got %q, want %q", mimeType, want)
	}

	mimeType = Sniff([]byte{0x01})
	if want := "application/octet-stream"; mimeType != want {
		t.Errorf("got %q, want %q", mimeType, want)
	}

	mimeType = Sniff([]byte{0xff, 0xf1})
	if want := "audio/aac"; mimeType != want {
		t.Errorf("got %q, want %q", mimeType, want)
	}

	mimeType = Sniff([]byte("foobar"))
	if want := "text/plain; charset=utf-8"; mimeType != want {
		t.Errorf("got %q, want %q", mimeType, want)
	}
}

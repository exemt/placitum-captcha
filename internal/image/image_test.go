package image

import (
	"bytes"
	"image/png"
	"testing"
)

func TestRender(t *testing.T) {
	text := Text("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 5)
	if len(text) != 5 {
		t.Fatalf("text %q", text)
	}

	data := Render(text)
	if !bytes.HasPrefix(data, []byte("\x89PNG")) {
		t.Fatal("not a png")
	}

	if len(data) < 500 {
		t.Fatalf("suspiciously small: %d bytes", len(data))
	}

	t.Logf("png bytes: %d", len(data))
}

func TestRenderDecodes(t *testing.T) {
	out := Render("ABC23")

	if _, err := png.Decode(bytes.NewReader(out)); err != nil {
		t.Fatalf("png does not decode: %v (%d bytes)", err, len(out))
	}
}

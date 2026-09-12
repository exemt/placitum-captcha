package image

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAudioRoundTrip(t *testing.T) {
	dir := t.TempDir()

	for _, ch := range []string{"a", "b"} {
		pcm := make([]int16, 800)
		for i := range pcm {
			pcm[i] = int16((i % 50) * 100)
		}

		if err := os.WriteFile(filepath.Join(dir, ch+".wav"), encodeWav(8000, pcm), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if !HasSamples(dir) {
		t.Fatal("samples not detected")
	}

	out, err := Audio(dir, "AB")
	if err != nil {
		t.Fatal(err)
	}

	w, err := readWav(filepath.Join(dir, "a.wav"))
	if err != nil || w.rate != 8000 || len(w.pcm) != 800 {
		t.Fatalf("readWav: %v %+v", err, w)
	}

	if len(out) < 44+2*1600 {
		t.Fatalf("too short: %d", len(out))
	}

	if _, err := Audio(dir, "AZ"); err == nil {
		t.Fatal("missing sample accepted")
	}

	if HasSamples(filepath.Join(dir, "nope")) {
		t.Fatal("missing dir detected as samples")
	}
}

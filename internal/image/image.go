package image

import (
	"bytes"
	"crypto/rand"
	"image"
	"image/color"
	"image/png"
	"math"
	"math/big"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

const (
	scale  = 5
	glyphW = 7 * scale
	glyphH = 13 * scale
	padX   = 12
	padY   = 14
)

func Text(alphabet string, length int) string {
	out := make([]byte, length)
	n := big.NewInt(int64(len(alphabet)))

	for i := range out {
		v, err := rand.Int(rand.Reader, n)
		if err != nil {
			panic("captcha: crypto/rand is unavailable: " + err.Error())
		}

		out[i] = alphabet[v.Int64()]
	}

	return string(out)
}

func Render(text string) []byte {
	w := padX*2 + glyphW*len(text)
	h := padY*2 + glyphH

	mask := image.NewGray(image.Rect(0, 0, 7*len(text), 13))
	d := font.Drawer{
		Dst:  mask,
		Src:  image.White,
		Face: basicfont.Face7x13,
		Dot:  fixed.P(0, 11),
	}
	d.DrawString(text)

	out := image.NewRGBA(image.Rect(0, 0, w, h))
	bg := color.RGBA{R: 0xf6, G: 0xf6, B: 0xf2, A: 0xff}
	fg := color.RGBA{R: 0x22, G: 0x2a, B: 0x44, A: 0xff}

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			out.SetRGBA(x, y, bg)
		}
	}

	phase1 := randFloat() * 2 * math.Pi
	phase2 := randFloat() * 2 * math.Pi
	ampX := 3.0 + randFloat()*3
	ampY := 2.0 + randFloat()*3

	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			sx := float64(x-padX) + ampX*math.Sin(float64(y)/11.0+phase1)
			sy := float64(y-padY) + ampY*math.Sin(float64(x)/17.0+phase2)

			mx := int(sx) / scale
			my := int(sy) / scale

			if sx < 0 || sy < 0 || mx >= mask.Bounds().Dx() || my >= mask.Bounds().Dy() {
				continue
			}

			if mask.GrayAt(mx, my).Y > 128 {
				out.SetRGBA(x, y, fg)
			}
		}
	}

	noise(out, fg)

	var buf bytes.Buffer
	_ = png.Encode(&buf, out)

	return buf.Bytes()
}

func noise(img *image.RGBA, c color.RGBA) {
	b := img.Bounds()
	line := color.RGBA{R: c.R, G: c.G, B: c.B, A: 0x90}

	for i := 0; i < 3; i++ {
		x0 := randInt(b.Dx())
		y0 := randInt(b.Dy())
		x1 := randInt(b.Dx())
		y1 := randInt(b.Dy())
		steps := max(abs(x1-x0), abs(y1-y0), 1)

		for s := 0; s <= steps; s++ {
			x := x0 + (x1-x0)*s/steps
			y := y0 + (y1-y0)*s/steps
			img.SetRGBA(x, y, line)

			if y+1 < b.Dy() {
				img.SetRGBA(x, y+1, line)
			}
		}
	}

	dots := b.Dx() * b.Dy() / 60

	for i := 0; i < dots; i++ {
		img.SetRGBA(randInt(b.Dx()), randInt(b.Dy()), line)
	}
}

func randInt(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}

	return int(v.Int64())
}

func randFloat() float64 {
	return float64(randInt(1<<20)) / float64(1<<20)
}

func abs(v int) int {
	if v < 0 {
		return -v
	}

	return v
}

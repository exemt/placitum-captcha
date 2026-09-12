/*
 * Аудио-вариант картинки: произнесённые символы из каталога сэмплов.
 *
 * Синтезировать речь в образе нечем, поэтому голос приносит оператор:
 * каталог с файлами <символ>.wav (нижний регистр, 16-bit PCM mono, одна
 * частота дискретизации на всех). Сервис склеивает их со случайными паузами
 * и лёгким шумом -- чтобы склейку нельзя было распознать по байтам.
 *
 * Нет каталога -- нет аудио: флаг audio профиля в этом случае ничего не
 * обещает, и страница кнопку не показывает.
 */

package image

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	minGapMS = 150
	maxGapMS = 450
	noiseAmp = 300
)

type wav struct {
	rate int
	pcm  []int16
}

// HasSamples -- есть ли каталог и хотя бы один сэмпл.
func HasSamples(dir string) bool {
	if dir == "" {
		return false
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".wav") {
			return true
		}
	}

	return false
}

// Audio -- WAV для текста. Символ без сэмпла -- ошибка: лучше не отдать
// аудио вовсе, чем произнести половину.
func Audio(dir, text string) ([]byte, error) {
	var (
		rate int
		out  []int16
	)

	out = append(out, silence(0, 300)...)

	for _, r := range strings.ToLower(text) {
		w, err := readWav(filepath.Join(dir, string(r)+".wav"))
		if err != nil {
			return nil, err
		}

		if rate == 0 {
			rate = w.rate
		} else if rate != w.rate {
			return nil, errors.New("audio samples disagree on sample rate")
		}

		out = append(out, w.pcm...)
		out = append(out, silence(rate, minGapMS+randInt(maxGapMS-minGapMS))...)
	}

	if rate == 0 {
		return nil, errors.New("no samples")
	}

	for i := range out {
		n := int32(out[i]) + int32(randInt(2*noiseAmp)-noiseAmp)

		if n > 32767 {
			n = 32767
		} else if n < -32768 {
			n = -32768
		}

		out[i] = int16(n)
	}

	return encodeWav(rate, out), nil
}

func silence(rate, ms int) []int16 {
	if rate == 0 {
		rate = 8000
	}

	return make([]int16, rate*ms/1000)
}

// readWav разбирает RIFF/WAVE с чанком fmt (PCM 16 бит, моно) и data.
func readWav(path string) (*wav, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if len(raw) < 12 || string(raw[0:4]) != "RIFF" || string(raw[8:12]) != "WAVE" {
		return nil, errors.New(path + ": not a WAV")
	}

	var (
		rate     int
		channels int
		bits     int
		data     []byte
	)

	for p := 12; p+8 <= len(raw); {
		id := string(raw[p : p+4])
		size := int(binary.LittleEndian.Uint32(raw[p+4 : p+8]))
		body := raw[p+8:]

		if size > len(body) {
			size = len(body)
		}

		switch id {
		case "fmt ":
			if size < 16 {
				return nil, errors.New(path + ": short fmt chunk")
			}

			channels = int(binary.LittleEndian.Uint16(body[2:4]))
			rate = int(binary.LittleEndian.Uint32(body[4:8]))
			bits = int(binary.LittleEndian.Uint16(body[14:16]))

		case "data":
			data = body[:size]
		}

		p += 8 + size + size%2
	}

	if rate == 0 || data == nil {
		return nil, errors.New(path + ": no fmt or data chunk")
	}

	if channels != 1 || bits != 16 {
		return nil, errors.New(path + ": want 16-bit PCM mono")
	}

	pcm := make([]int16, len(data)/2)

	for i := range pcm {
		pcm[i] = int16(binary.LittleEndian.Uint16(data[2*i:]))
	}

	return &wav{rate: rate, pcm: pcm}, nil
}

func encodeWav(rate int, pcm []int16) []byte {
	var buf bytes.Buffer
	dataLen := uint32(len(pcm) * 2)

	buf.WriteString("RIFF")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(36+dataLen))
	buf.WriteString("WAVEfmt ")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(16))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1)) // PCM
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1)) // mono
	_ = binary.Write(&buf, binary.LittleEndian, uint32(rate))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(rate*2))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(2))
	_ = binary.Write(&buf, binary.LittleEndian, uint16(16))
	buf.WriteString("data")
	_ = binary.Write(&buf, binary.LittleEndian, dataLen)
	_ = binary.Write(&buf, binary.LittleEndian, pcm)

	return buf.Bytes()
}

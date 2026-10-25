package protocol

import (
	"bytes"
	"testing"
)

func TestChunkHeaderRoundtrip(t *testing.T) {
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i)
	}
	hdr := EncodeChunkHeader("file-1234", 4096, 256<<10, hash)
	id, off, ln, gotHash, err := DecodeChunkHeader(hdr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if id != "file-1234" || off != 4096 || ln != 256<<10 || gotHash != hash {
		t.Fatalf("roundtrip mismatch: %q %d %d", id, off, ln)
	}
}

func TestChunkHeaderRejectsGarbage(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("short"),
		append([]byte("XXXXXXXX"), bytes.Repeat([]byte{0}, 64)...), // bad magic
	}
	for i, b := range cases {
		if _, _, _, _, err := DecodeChunkHeader(b); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

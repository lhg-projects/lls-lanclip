package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"
)

// Client pushes to another daemon's HTTP face (Android peers) with the
// group-key HMAC. The phone face is plain HTTP on the LAN: authenticity
// comes from the HMAC, confidentiality from LAN trust.
type Client struct {
	base string
	key  []byte
	hc   *http.Client
}

// NewClient targets base ("http://ip:port") with the group key.
func NewClient(base string, groupKey []byte) *Client {
	return &Client{base: base, key: groupKey, hc: &http.Client{Timeout: 120 * time.Second}}
}

func (c *Client) do(method, path string, body []byte, contentType string) ([]byte, error) {
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	ts := nowMilli()
	req.Header.Set("X-Lanclip-Ts", strconv.FormatInt(ts, 10))
	req.Header.Set("Authorization", Sign(c.key, ts, method, path, body))
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return out, fmt.Errorf("http %d: %s", resp.StatusCode, string(out))
	}
	return out, nil
}

// Ping checks reachability.
func (c *Client) Ping() error {
	_, err := c.do(http.MethodGet, "/api/ping", nil, "")
	return err
}

// SendText pushes a text clipboard update.
func (c *Client) SendText(text string) error {
	b, _ := json.Marshal(map[string]string{"text": text})
	_, err := c.do(http.MethodPost, "/api/send-text", b, "application/json")
	return err
}

// SendImage pushes a PNG (base64) to the peer's clipboard/gallery.
func (c *Client) SendImage(pngBase64 string) error {
	b, _ := json.Marshal(map[string]string{"png_base64": pngBase64})
	_, err := c.do(http.MethodPost, "/api/shot", b, "application/json")
	return err
}

// SendFile uploads one file as multipart/form-data.
func (c *Client) SendFile(filename string, content []byte) error {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		return err
	}
	if _, err := fw.Write(content); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	_, err = c.do(http.MethodPost, "/api/send-file", buf.Bytes(), w.FormDataContentType())
	return err
}

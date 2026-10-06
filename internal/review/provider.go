package review

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Provider sends one review request and returns the model's text.
type Provider interface {
	Complete(ctx context.Context, model, system, user string) (string, error)
	Name() string
}

// OpenAI speaks the Chat Completions API (OpenAI and compatible servers).
type OpenAI struct {
	BaseURL string // default https://api.openai.com/v1
	APIKey  string
	HTTP    *http.Client
}

// Name implements Provider.
func (OpenAI) Name() string { return "openai" }

// Complete implements Provider. It asks for a JSON object answer.
func (o OpenAI) Complete(ctx context.Context, model, system, user string) (string, error) {
	base := strings.TrimRight(o.BaseURL, "/")
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	body := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"response_format": map[string]string{"type": "json_object"},
	}
	var resp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	hdr := map[string]string{"Authorization": "Bearer " + o.APIKey}
	if err := post(ctx, o.HTTP, base+"/chat/completions", hdr, body, &resp); err != nil {
		return "", err
	}
	if len(resp.Choices) == 0 {
		return "", errors.New("openai: no choices in the answer")
	}
	if fr := resp.Choices[0].FinishReason; fr != "" && fr != "stop" {
		return "", fmt.Errorf("openai: answer ended with %q", fr)
	}
	return resp.Choices[0].Message.Content, nil
}

// Anthropic speaks the Messages API.
type Anthropic struct {
	BaseURL   string // default https://api.anthropic.com/v1
	APIKey    string
	MaxTokens int
	HTTP      *http.Client
}

// Name implements Provider.
func (Anthropic) Name() string { return "anthropic" }

// Complete implements Provider.
func (a Anthropic) Complete(ctx context.Context, model, system, user string) (string, error) {
	base := strings.TrimRight(a.BaseURL, "/")
	if base == "" {
		base = "https://api.anthropic.com/v1"
	}
	max := a.MaxTokens
	if max == 0 {
		max = 8192
	}
	body := map[string]any{
		"model": model, "max_tokens": max, "system": system,
		"messages": []map[string]string{{"role": "user", "content": user}},
	}
	var resp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StopReason string `json:"stop_reason"`
	}
	hdr := map[string]string{"x-api-key": a.APIKey, "anthropic-version": "2023-06-01"}
	if err := post(ctx, a.HTTP, base+"/messages", hdr, body, &resp); err != nil {
		return "", err
	}
	if resp.StopReason != "" && resp.StopReason != "end_turn" {
		return "", fmt.Errorf("anthropic: answer ended with %q", resp.StopReason)
	}
	var b strings.Builder
	for _, c := range resp.Content {
		if c.Type == "text" {
			b.WriteString(c.Text)
		}
	}
	return b.String(), nil
}

func post(ctx context.Context, hc *http.Client, url string, hdr map[string]string, body, out any) error {
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Minute}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		// The body may echo the request; only the status is reported.
		return fmt.Errorf("model API answered %d", resp.StatusCode)
	}
	return json.Unmarshal(rb, out)
}

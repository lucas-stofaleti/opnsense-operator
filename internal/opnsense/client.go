package opnsense

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

var (
	ErrAliasNotFound      = errors.New("opnsense alias not found")
	ErrValidationFailed   = errors.New("opnsense validation failed")
	ErrUnexpectedResponse = errors.New("unexpected opnsense response")
)

type Client struct {
	baseURL    string
	apiKey     string
	apiSecret  string
	httpClient *http.Client
}

type Alias struct {
	Enabled     bool
	Name        string
	Type        string
	Content     string
	Description string
}

type ValidationError struct {
	FieldErrors map[string]string
}

func (e *ValidationError) Error() string {
	if len(e.FieldErrors) == 0 {
		return ErrValidationFailed.Error()
	}

	keys := make([]string, 0, len(e.FieldErrors))
	for key := range e.FieldErrors {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s: %s", key, e.FieldErrors[key]))
	}

	return fmt.Sprintf("%s: %s", ErrValidationFailed, strings.Join(parts, ", "))
}

func (e *ValidationError) Unwrap() error {
	return ErrValidationFailed
}

func AsValidationError(err error, target **ValidationError) bool {
	return errors.As(err, target)
}

func NewClient(baseURL, apiKey, apiSecret string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		apiSecret:  apiSecret,
		httpClient: httpClient,
	}
}

func (c *Client) GetAliasUUIDByName(ctx context.Context, name string) (string, error) {
	body, err := c.doJSON(ctx, http.MethodGet, "/api/firewall/alias/getAliasUUID/"+name, nil)
	if err != nil {
		return "", err
	}

	trimmed := bytes.TrimSpace(body)
	if bytes.Equal(trimmed, []byte("[]")) {
		return "", ErrAliasNotFound
	}

	var response struct {
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal(trimmed, &response); err != nil {
		return "", fmt.Errorf("decode alias uuid response: %w", err)
	}
	if response.UUID == "" {
		return "", fmt.Errorf("%w: alias uuid response did not contain a uuid", ErrUnexpectedResponse)
	}

	return response.UUID, nil
}

func (c *Client) GetAlias(ctx context.Context, uuid string) (Alias, error) {
	body, err := c.doJSON(ctx, http.MethodGet, "/api/firewall/alias/export?ids="+url.QueryEscape(uuid), nil)
	if err != nil {
		return Alias{}, err
	}

	var response struct {
		Aliases struct {
			Alias json.RawMessage `json:"alias"`
		} `json:"aliases"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return Alias{}, fmt.Errorf("decode export alias response: %w", err)
	}

	aliasData := bytes.TrimSpace(response.Aliases.Alias)
	if len(aliasData) == 0 {
		return Alias{}, fmt.Errorf("%w: export alias response did not contain alias data", ErrUnexpectedResponse)
	}

	switch aliasData[0] {
	case '[':
		var aliases []any
		if err := json.Unmarshal(aliasData, &aliases); err != nil {
			return Alias{}, fmt.Errorf("decode exported alias array: %w", err)
		}
		if len(aliases) == 0 {
			return Alias{}, ErrAliasNotFound
		}
		return Alias{}, fmt.Errorf("%w: export alias response returned an unexpected array", ErrUnexpectedResponse)
	case '{':
		var aliases map[string]struct {
			Enabled     string `json:"enabled"`
			Name        string `json:"name"`
			Type        string `json:"type"`
			Content     string `json:"content"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(aliasData, &aliases); err != nil {
			return Alias{}, fmt.Errorf("decode exported alias object: %w", err)
		}
		if len(aliases) == 0 {
			return Alias{}, ErrAliasNotFound
		}

		exportedAlias, ok := aliases[uuid]
		if !ok {
			return Alias{}, fmt.Errorf("%w: export alias response did not contain requested uuid %q", ErrUnexpectedResponse, uuid)
		}
		if exportedAlias.Name == "" {
			return Alias{}, fmt.Errorf("%w: exported alias did not contain a name", ErrUnexpectedResponse)
		}
		if exportedAlias.Type == "" {
			return Alias{}, fmt.Errorf("%w: exported alias did not contain a type", ErrUnexpectedResponse)
		}

		return Alias{
			Enabled:     exportedAlias.Enabled == "1",
			Name:        exportedAlias.Name,
			Type:        exportedAlias.Type,
			Content:     exportedAlias.Content,
			Description: exportedAlias.Description,
		}, nil
	default:
		return Alias{}, fmt.Errorf("%w: export alias response had unexpected alias payload", ErrUnexpectedResponse)
	}
}

func (c *Client) CreateAlias(ctx context.Context, alias Alias) (string, error) {
	body, err := c.doJSON(ctx, http.MethodPost, "/api/firewall/alias/addItem", aliasRequest{
		Alias: encodeAlias(alias),
	})
	if err != nil {
		return "", err
	}

	response, err := decodeResultResponse(body)
	if err != nil {
		return "", err
	}
	if err := response.resultError("saved"); err != nil {
		return "", err
	}
	if response.UUID == "" {
		return "", fmt.Errorf("%w: create alias response did not contain a uuid", ErrUnexpectedResponse)
	}

	return response.UUID, nil
}

func (c *Client) UpdateAlias(ctx context.Context, uuid string, alias Alias) error {
	body, err := c.doJSON(ctx, http.MethodPost, "/api/firewall/alias/setItem/"+uuid, aliasRequest{
		Alias: encodeAlias(alias),
	})
	if err != nil {
		return err
	}

	response, err := decodeResultResponse(body)
	if err != nil {
		return err
	}
	if response.Result == "failed" && len(response.Validations) == 0 {
		return ErrAliasNotFound
	}

	return response.resultError("saved")
}

func (c *Client) DeleteAlias(ctx context.Context, uuid string) error {
	body, err := c.doJSON(ctx, http.MethodPost, "/api/firewall/alias/delItem/"+uuid, map[string]string{})
	if err != nil {
		return err
	}

	response, err := decodeResultResponse(body)
	if err != nil {
		return err
	}
	if response.Result == "not found" {
		return ErrAliasNotFound
	}

	return response.resultError("deleted")
}

func (c *Client) CheckConnectivity(ctx context.Context) error {
	body, err := c.doJSON(ctx, http.MethodGet, "/api/core/system/status", nil)
	if err != nil {
		return err
	}

	// Verify the response is valid JSON. The content of the body reflects
	// OPNsense system health, which is unrelated to API connectivity.
	var response map[string]any
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("%w: connectivity check response is not valid JSON", ErrUnexpectedResponse)
	}

	return nil
}

func (c *Client) ReconfigureAliases(ctx context.Context) error {
	body, err := c.doJSON(ctx, http.MethodPost, "/api/firewall/alias/reconfigure", map[string]string{})
	if err != nil {
		return err
	}

	var response struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return fmt.Errorf("decode reconfigure response: %w", err)
	}
	if response.Status != "ok" {
		return fmt.Errorf("%w: expected reconfigure status ok, got %q", ErrUnexpectedResponse, response.Status)
	}

	return nil
}

type aliasRequest struct {
	Alias aliasPayload `json:"alias"`
}

type aliasPayload struct {
	Enabled     string `json:"enabled"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Content     string `json:"content"`
	Description string `json:"description,omitempty"`
}

func encodeAlias(alias Alias) aliasPayload {
	enabled := "0"
	if alias.Enabled {
		enabled = "1"
	}

	return aliasPayload{
		Enabled:     enabled,
		Name:        alias.Name,
		Type:        alias.Type,
		Content:     alias.Content,
		Description: alias.Description,
	}
}

type resultResponse struct {
	Result      string            `json:"result"`
	Status      string            `json:"status"`
	UUID        string            `json:"uuid"`
	Validations map[string]string `json:"validations"`
}

func decodeResultResponse(body []byte) (resultResponse, error) {
	var response resultResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return resultResponse{}, fmt.Errorf("decode result response: %w", err)
	}

	return response, nil
}

func (r resultResponse) resultError(expected string) error {
	if r.Result == "failed" {
		return &ValidationError{FieldErrors: r.Validations}
	}
	if r.Result != expected {
		return fmt.Errorf("%w: expected result %q, got %q", ErrUnexpectedResponse, expected, r.Result)
	}

	return nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(c.apiKey, c.apiSecret)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	return responseBody, nil
}

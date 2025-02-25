package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		setHeader string
		expectKey string
		expectErr error
	}{
		{
			name:      "Valid API key",
			setHeader: "ApiKey abc123",
			expectKey: "abc123",
			expectErr: nil,
		},
		{
			name:      "No Authorization header",
			setHeader: "",
			expectKey: "",
			expectErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "Malformed Authorization header",
			setHeader: "Bearer abc123",
			expectKey: "",
			expectErr: nil,
		},
		{
			name:      "Missing API key",
			setHeader: "ApiKey",
			expectKey: "",
			expectErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.setHeader != "" {
				headers.Set("Authorization", tt.setHeader)
			}

			key, err := GetAPIKey(headers)

			if key != tt.expectKey {
				t.Errorf("expected key %q, got %q", tt.expectKey, key)
			}

			if (err != nil && tt.expectErr == nil) || (err == nil && tt.expectErr != nil) || (err != nil && err.Error() != tt.expectErr.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectErr, err)
			}
		})
	}
}

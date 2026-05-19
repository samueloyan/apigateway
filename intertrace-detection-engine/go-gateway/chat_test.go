package main

import "testing"

func TestResolveProviderByModel(t *testing.T) {
	tests := []struct {
		model    string
		expected string
	}{
		{model: "gpt-5.5", expected: defaultProviderOpenAI},
		{model: "claude-3-7-sonnet", expected: defaultProviderAnthrop},
		{model: "gemini-2.5-pro", expected: defaultProviderGemini},
	}

	for _, tc := range tests {
		provider, err := resolveProvider("", tc.model, map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error for model %s: %v", tc.model, err)
		}
		if provider != tc.expected {
			t.Fatalf("expected %s for model %s, got %s", tc.expected, tc.model, provider)
		}
	}
}

func TestExtractTextContentFromArray(t *testing.T) {
	content := []interface{}{
		map[string]interface{}{"type": "text", "text": "hello"},
		map[string]interface{}{"type": "input_text", "text": "world"},
	}
	got, err := extractTextContent(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hello\nworld" {
		t.Fatalf("expected joined text content, got %q", got)
	}
}

func TestBuildDetectionInput(t *testing.T) {
	input := buildDetectionInput([]normalizedMessage{
		{Role: "system", Content: "policy"},
		{Role: "user", Content: "hello"},
	})
	expected := "system: policy\nuser: hello"
	if input != expected {
		t.Fatalf("expected %q, got %q", expected, input)
	}
}

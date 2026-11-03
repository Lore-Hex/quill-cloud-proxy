package main

import (
	"bufio"
	"strings"
	"testing"
)

func TestNYTETitleOutranksTheOtherTitlesInAnyOrder(t *testing.T) {
	headers := []string{"X-Title: Legacy\r\n", "X-OpenRouter-Title: OpenRouter\r\n", "X-NYTE-Title: Exchange\r\n"}
	orders := [][]int{{0, 1, 2}, {2, 1, 0}, {1, 2, 0}, {2, 0, 1}}
	for _, order := range orders {
		raw := "POST /v1/chat/completions HTTP/1.1\r\n"
		for _, index := range order {
			raw += headers[index]
		}
		raw += "Content-Length: 2\r\n\r\n{}"
		_, _, _, _, attribution, _, err := readRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			t.Fatalf("%v: readRequest: %v", order, err)
		}
		if attribution.App != "Exchange" {
			t.Fatalf("%v: App = %q, want the X-NYTE-Title", order, attribution.App)
		}
	}
	raw := "POST /v1/chat/completions HTTP/1.1\r\nX-OpenRouter-Title: OpenRouter\r\nX-Title: Legacy\r\nContent-Length: 2\r\n\r\n{}"
	_, _, _, _, attribution, _, err := readRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil || attribution.App != "OpenRouter" {
		t.Fatalf("without X-NYTE-Title: App = %q, err = %v", attribution.App, err)
	}
}

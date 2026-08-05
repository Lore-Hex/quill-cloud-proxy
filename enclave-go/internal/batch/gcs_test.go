package batch

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type fixedAccessToken string

func (token fixedAccessToken) Token(context.Context) (string, error) { return string(token), nil }

func TestGCSStoreUsesGenerationPreconditionsAndEscapedNames(t *testing.T) {
	t.Parallel()

	var requests int
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Header.Get("Authorization") != "Bearer access-token" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		switch requests {
		case 1:
			if request.Method != http.MethodPost || request.URL.Query().Get("ifGenerationMatch") != "0" || request.URL.Query().Get("name") != "prefix/a b.json" {
				t.Fatalf("put request = %s %s", request.Method, request.URL.String())
			}
			return jsonResponse(200, `{"generation":"41"}`), nil
		case 2:
			if request.Method != http.MethodGet || request.URL.Query().Get("alt") != "media" || !strings.Contains(request.URL.EscapedPath(), "prefix%2Fa%20b.json") {
				t.Fatalf("get request = %s %s escaped=%s", request.Method, request.URL.String(), request.URL.EscapedPath())
			}
			response := jsonResponse(200, "stored")
			response.Header.Set("X-Goog-Generation", "41")
			return response, nil
		case 3:
			if request.Method != http.MethodDelete || request.URL.Query().Get("ifGenerationMatch") != "41" {
				t.Fatalf("delete request = %s %s", request.Method, request.URL.String())
			}
			return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
		default:
			t.Fatalf("unexpected request %d", requests)
			return nil, nil
		}
	})}
	store := NewGCSStoreForTest("bucket", client, fixedAccessToken("access-token"))

	created, err := store.Put(t.Context(), "prefix/a b.json", []byte("stored"), PutCondition{Generation: 0})
	if err != nil || created.Generation != 41 {
		t.Fatalf("Put = %#v, %v", created, err)
	}
	read, err := store.Get(t.Context(), "prefix/a b.json")
	if err != nil || read.Generation != 41 || string(read.Data) != "stored" {
		t.Fatalf("Get = %#v, %v", read, err)
	}
	if err := store.Delete(t.Context(), "prefix/a b.json", 41); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

func TestGCSStoreListsObjectsAndMapsConditionalFailures(t *testing.T) {
	t.Parallel()

	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			if request.URL.Query().Get("prefix") != activePrefix || request.URL.Query().Get("maxResults") != "25" {
				t.Fatalf("list query = %s", request.URL.RawQuery)
			}
			return jsonResponse(200, `{"items":[{"name":"a","generation":"2"},{"name":"bad","generation":"nope"},{"name":"b","generation":"3"}]}`), nil
		}
		return jsonResponse(http.StatusPreconditionFailed, `{}`), nil
	})}
	store := NewGCSStoreForTest("bucket", client, fixedAccessToken("token"))
	objects, nextPageToken, err := store.List(t.Context(), activePrefix, 25, "")
	if err != nil || len(objects) != 2 || objects[0].Generation != 2 || objects[1].Name != "b" {
		t.Fatalf("List = %#v, %v", objects, err)
	}
	if nextPageToken != "" {
		t.Fatalf("next page token = %q, want empty", nextPageToken)
	}
	if _, err := store.Put(t.Context(), "a", nil, PutCondition{Generation: 2}); err != ErrPrecondition {
		t.Fatalf("Put error = %v", err)
	}
	if err := store.Delete(t.Context(), "a", 2); err != ErrPrecondition {
		t.Fatalf("Delete error = %v", err)
	}
}

func TestGCSStoreBoundsObjectReads(t *testing.T) {
	t.Parallel()

	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		response := jsonResponse(http.StatusOK, "12345")
		response.Header.Set("X-Goog-Generation", "1")
		return response, nil
	})}
	store := NewGCSStoreForTest("bucket", client, fixedAccessToken("token"))
	store.maxObjectBytes = 4
	if _, err := store.Get(t.Context(), "too-large"); err == nil || !strings.Contains(err.Error(), "object too large") {
		t.Fatalf("Get error = %v", err)
	}
}

func TestGCSStoreRejectsOversizedPutBeforeTokenOrNetwork(t *testing.T) {
	t.Parallel()

	store := NewGCSStoreForTest("batch-bucket", nil, nil)
	store.maxObjectBytes = 3
	if _, err := store.Put(t.Context(), "object", []byte("four"), PutCondition{Generation: 0}); err == nil || !strings.Contains(err.Error(), "object too large") {
		t.Fatalf("Put error = %v, want object-too-large", err)
	}
}

package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/llm"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/upstreamerror"
)

func TestRouteFallbackRetainsSafeUpstreamDiagnosis(t *testing.T) {
	selected := newSelectedRouteTracker()
	selected.RecordFallbackFailure(llm.InvokeOptions{Provider: "provider", EndpointID: "route"},
		&upstreamerror.Error{Status: 400, Body: `{"error":{"message":"PRIVATE PROMPT","code":"unsupported_parameter","param":"reasoning_effort"}}`})
	want := "provider|route|upstream_4xx;http=400;code=unsupported_parameter;param=reasoning_effort"
	if got := selected.Failures(); len(got) != 1 || got[0] != want {
		t.Fatalf("failure = %q, want %q", got, want)
	}
}

func TestRouteFallbackTelemetryIsBoundedAndContentFree(t *testing.T) {
	client := &scriptedProviderStreamClient{invoke: func(option llm.InvokeOptions, out io.Writer) error {
		if option.EndpointID != "success" {
			return errors.New("http 503 PRIVATE-PROMPT PRIVATE-KEY")
		}
		_, err := io.WriteString(out, providerStreamTestResponse)
		return err
	}}
	options := make([]llm.InvokeOptions, 0, 11)
	for i := range 10 {
		options = append(options, llm.InvokeOptions{Model: "model", Provider: "provider", EndpointID: fmt.Sprintf("failed-%d", i)})
	}
	options = append(options, llm.InvokeOptions{Model: "model", Provider: "provider", EndpointID: "success"})
	_, err, selected := runProviderStreamTest(t, client, options)
	if err != nil {
		t.Fatal(err)
	}
	failures := selected.Failures()
	if selected.FallbackCount() != 10 || len(failures) != 8 {
		t.Fatalf("count=%d failures=%q", selected.FallbackCount(), failures)
	}
	for i, failure := range failures {
		if want := fmt.Sprintf("provider|failed-%d|upstream_5xx", i); failure != want {
			t.Fatalf("failure=%q want=%q", failure, want)
		}
	}
	failures[0] = "changed"
	if strings.Contains(strings.Join(selected.Failures(), ","), "changed") {
		t.Fatal("returned failures alias mutable tracker state")
	}
}

func TestTerminalFailureIsNotReportedAsSuccessfulFallback(t *testing.T) {
	client := &scriptedProviderStreamClient{invoke: func(llm.InvokeOptions, io.Writer) error {
		return errors.New("http 503 PRIVATE-PROMPT")
	}}
	_, err, selected := runProviderStreamTest(t, client, []llm.InvokeOptions{{Model: "model", EndpointID: "only"}})
	if err == nil || len(selected.Failures()) != 0 || selected.FallbackCount() != 0 {
		t.Fatalf("error=%v count=%d failures=%q", err, selected.FallbackCount(), selected.Failures())
	}
}

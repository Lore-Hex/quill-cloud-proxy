//go:build live_decide

package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/adapter"
	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/decide"
)

// Paid eval, a fraction of a cent per model:
//
//	go test -tags live_decide -run TestLiveDecide -v ./internal/llm/
//
// Native decision models are CHOSEN with this file, not with a capability
// table. Every answer must survive decide.Verify (structure) and is then scored
// against labeled support tickets (judgment). To try a model that is not yet in
// decide.NativeModels:
//
//	TR_LIVE_DECIDE_CANDIDATES='model|provider|upstream|effort|format;...'
//
// Build with BOTH live tags (the stream reader is shared with the provider-wave
// probe), and a multi-provider cloud build:
//
//	go test -tags "live_decide live_provider_wave llm_multi cloud_gcp" ./internal/llm/ -run TestLiveDecide -v

const liveQuestions = `{
 "refund":  {"type":"boolean","instructions":"Is the customer asking for money back or for a charge to be reversed?"},
 "damaged": {"type":"boolean","instructions":"Does the customer say a physical item arrived damaged?"},
 "route":   {"type":"choice","instructions":"Route this support ticket.","criteria":{"billing":"payment, charge or subscription problems","shipping":"delivery or physical package problems","technical":"application bugs and outages"}},
 "urgency": {"type":"score","instructions":"How urgent is this ticket?","criteria":["low: no time pressure","medium: wants it soon","high: demands action today or is blocked right now"]}
}`

type liveCase struct {
	state                  string
	refund, damaged        string  // "yes" | "no" | "" (unlabeled)
	route                  string  // "" = unlabeled
	urgencyMin, urgencyMax float64 // score bounds; -1 = unlabeled
}

var liveCases = []liveCase{
	{"I was charged twice for order A-1 and I need this fixed today, I am furious.", "yes", "no", "billing", 1.3, -1},
	{"My package arrived with the box crushed and the screen cracked. Can you send a replacement? No rush.", "no", "yes", "shipping", -1, 0.9},
	{"The app crashes every time I open the settings page on Android 15.", "no", "no", "technical", -1, -1},
	{"Where is my order? Tracking has not updated in 9 days and I need it for a wedding on Saturday.", "no", "no", "shipping", 1.2, -1},
	{"Please cancel my subscription and refund this month's payment, I never used it.", "yes", "no", "billing", -1, -1},
	{"Login shows error 500 since this morning; our whole team is locked out and we demo to a client in one hour!", "no", "no", "technical", 1.5, -1},
	{"Just wanted to say the new dashboard looks great. One small thing: the export button is slightly misaligned on Safari.", "no", "no", "technical", -1, 0.8},
	{"You billed my card $49 but my plan is $29. Not urgent, just correct it on the next invoice.", "", "no", "billing", -1, 1.0},
}

type liveCandidate struct {
	model, provider, upstream string
	native                    decide.NativeModel
}

var liveKeyEnv = map[string]string{
	"openai": "OPENAI_API_KEY", "deepinfra": "DEEPINFRA_API_KEY",
	"google-ai-studio": "GOOGLE_AI_STUDIO_KEY", "nscale": "NSCALE_API_KEY",
	"engy": "ENGY_API_KEY", "deepseek": "DEEPSEEK_API_KEY", "wafer": "WAFER_API_KEY",
	"cerebras": "CEREBRAS_API_KEY", "sambanova": "SAMBANOVA_API_KEY", "inception": "INCEPTION_API_KEY",
	"morph": "MORPH_API_KEY", "zai": "ZAI_API_KEY", "together": "TOGETHER_API_KEY", "fireworks": "FIREWORKS_API_KEY",
	"baseten": "BASETEN_API_KEY", "parasail": "PARASAIL_API_KEY", "gmi": "GMI_API_KEY", "novita": "NOVITA_API_KEY",
}

// liveUpstream is the provider-native id for each shipped native model.
var liveUpstream = map[string]string{
	"google/gemini-3.1-flash-lite": "gemini-3.1-flash-lite",
	"openai/gpt-oss-20b":           "openai/gpt-oss-20b",
	"google/gemma-4-e4b-it":        "google/gemma-4-E4B-it",
	"deepseek/deepseek-v4.1-flash": "deepseek-ai/DeepSeek-V4.1-Flash",
	decide.TrevModelID:             "gpt-oss-120b",
	// A name calls the same upstream as the chat model behind it.
	decide.GevModelID:                   "gemini-3.1-flash-lite",
	decide.DevModelID:                   "deepseek-ai/DeepSeek-V4.1-Flash",
	decide.OevModelID:                   "openai/gpt-oss-20b",
	decide.GemmevModelID:                "google/gemma-4-E4B-it",
	"inception/mercury-2":               "mercury-2",
	"z-ai/glm-5.2-fast":                 "accounts/fireworks/routers/glm-5p2-fast",
	"meta-llama/llama-3.3-70b-instruct": "Meta-Llama-3.3-70B-Instruct",
	decide.MevModelID:                   "mercury-2",
	decide.ZevModelID:                   "accounts/fireworks/routers/glm-5p2-fast",
	decide.LevModelID:                   "Meta-Llama-3.3-70B-Instruct",
}

func liveCandidates(t *testing.T) []liveCandidate {
	t.Helper()
	var out []liveCandidate
	if raw := strings.TrimSpace(os.Getenv("TR_LIVE_DECIDE_CANDIDATES")); raw != "" {
		zero := 0.0
		for _, item := range strings.Split(raw, ";") {
			parts := strings.Split(strings.TrimSpace(item), "|")
			if len(parts) != 5 {
				t.Fatalf("candidate %q: want model|provider|upstream|effort|format", item)
			}
			out = append(out, liveCandidate{parts[0], parts[1], parts[2], decide.NativeModel{
				Providers: []string{parts[1]}, ReasoningEffort: parts[3], Format: parts[4], Temperature: &zero,
			}})
		}
		return out
	}
	for model, native := range decide.NativeModels {
		upstream, ok := liveUpstream[model]
		if !ok {
			t.Fatalf("%s: add its upstream id to liveUpstream so the eval covers it", model)
		}
		// The eval measures the PREFERRED host; stand-ins are measured by name
		// through TR_LIVE_DECIDE_CANDIDATES.
		out = append(out, liveCandidate{model, native.Providers[0], upstream, native})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].model < out[j].model })
	return out
}

func liveSpecs(t *testing.T) (map[string]decide.Question, []decide.Spec) {
	t.Helper()
	var questions map[string]decide.Question
	if err := json.Unmarshal([]byte(liveQuestions), &questions); err != nil {
		t.Fatal(err)
	}
	specs, err := decide.Parse(questions)
	if err != nil {
		t.Fatal(err)
	}
	return questions, specs
}

// score returns (passed, total) labeled checks for one verified answer set.
func (c liveCase) score(answers map[string]decide.Answer) (int, int, []string) {
	passed, total := 0, 0
	var misses []string
	check := func(name string, ok bool, detail string) {
		total++
		if ok {
			passed++
		} else {
			misses = append(misses, name+"="+detail)
		}
	}
	for name, want := range map[string]string{"refund": c.refund, "damaged": c.damaged} {
		if want == "" {
			continue
		}
		p := *answers[name].Probability
		check(name, (want == "yes") == (p >= 0.5), fmt.Sprintf("%.2f", p))
	}
	if c.route != "" {
		check("route", *answers["route"].Choice == c.route, *answers["route"].Choice)
	}
	score := *answers["urgency"].Score
	if c.urgencyMin >= 0 {
		check("urgency>=", score >= c.urgencyMin, fmt.Sprintf("%.2f", score))
	}
	if c.urgencyMax >= 0 {
		check("urgency<=", score <= c.urgencyMax, fmt.Sprintf("%.2f", score))
	}
	return passed, total, misses
}

func liveUsage(raw []byte) (input, output int) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		var event struct {
			Message struct {
				Usage struct {
					InputTokens int `json:"input_tokens"`
				} `json:"usage"`
			} `json:"message"`
			Usage struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &event) == nil {
			input = max(input, event.Message.Usage.InputTokens, event.Usage.InputTokens)
			output = max(output, event.Usage.OutputTokens)
		}
	}
	return input, output
}

func TestLiveDecideNative(t *testing.T) {
	_, specs := liveSpecs(t)
	for _, candidate := range liveCandidates(t) {
		t.Run(candidate.model+"@"+candidate.provider, func(t *testing.T) {
			key := os.Getenv(liveKeyEnv[candidate.provider])
			if key == "" {
				t.Skipf("no key for provider %s", candidate.provider)
			}
			passed, total, invalid, inTok, outTok := 0, 0, 0, 0, 0
			var latencies []int
			for index, tc := range liveCases {
				state, _ := json.Marshal(tc.state)
				req, err := decide.NativeChatRequest(candidate.model, state, specs, candidate.native, decide.NativeOptions{})
				if err != nil {
					t.Fatal(err)
				}
				body, err := adapter.ToAnthropic(req, candidate.model)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
				var out bytes.Buffer
				started := time.Now()
				err = InvokeOpenAICompatibleStreaming(ctx, candidate.provider, directBaseURL(candidate.provider), key, req, body, &out, candidate.upstream)
				cancel()
				if err != nil {
					t.Fatalf("case %d: provider call failed: %v", index, err)
				}
				latencies = append(latencies, int(time.Since(started).Milliseconds()))
				// The route refunds any native attempt whose stream lacks a
				// terminal `event: message_stop` line or carries an
				// `event: error` line (cmd/enclave generationRecorder). If a real
				// host's stream were shaped differently, EVERY decision on it
				// would be refunded and fail, so that assumption is checked here
				// against the real thing.
				stops, errorEvents := 0, 0
				for _, line := range strings.Split(out.String(), "\n") {
					switch strings.TrimRight(line, "\r ") {
					case "event: message_stop":
						stops++
					case "event: error":
						errorEvents++
					}
				}
				if stops != 1 || errorEvents != 0 {
					t.Fatalf("case %d: stream has %d message_stop and %d error event lines; the route would refund this attempt", index, stops, errorEvents)
				}
				in, o := liveUsage(out.Bytes())
				inTok, outTok = inTok+in, outTok+o
				text, err := providerWaveVisibleText(out.Bytes())
				if err != nil {
					t.Fatal(err)
				}
				answers, err := decide.ExtractNative(specs, text)
				if err == nil {
					answers, err = decide.Verify(specs, answers)
				}
				if err != nil {
					invalid++
					t.Logf("case %d INVALID: %v | raw=%s", index, err, strings.Join(strings.Fields(text), " "))
					continue
				}
				p, n, misses := tc.score(answers)
				passed, total = passed+p, total+n
				if len(misses) > 0 {
					encoded, _ := json.Marshal(answers)
					t.Logf("case %d missed %v | state=%q | answers=%s", index, misses, tc.state, encoded)
				}
			}
			sort.Ints(latencies)
			n := len(liveCases)
			t.Logf("RESULT %-38s valid=%d/%d judgment=%d/%d latency_ms(median=%d max=%d) tokens/decision(in=%d out=%d)",
				candidate.model+"@"+candidate.provider, n-invalid, n, passed, total,
				latencies[len(latencies)/2], latencies[len(latencies)-1], inTok/n, outTok/n)
			if os.Getenv("TR_LIVE_DECIDE_CANDIDATES") != "" {
				return // exploring: report, do not gate
			}
			// A shipped model may need its one retry occasionally, but not often,
			// and must get the clearly labeled tickets right.
			if invalid > 1 {
				t.Errorf("%d of %d outputs failed the second pass", invalid, n)
			}
			if passed*100 < total*85 {
				t.Errorf("judgment %d/%d is below 85%%", passed, total)
			}
		})
	}
}

func TestLiveDecideHostedJev(t *testing.T) {
	// The same model through both of its hosts: TypeSafe's own API, and Vercel
	// AI Gateway, which relays it. Each must survive the second pass.
	hosts := []struct{ provider, keyEnv, baseURL, upstream string }{
		{"typesafe", "TYPESAFE_API_KEY", "https://api.typesafe.ai/v1", "jev-latest"},
		{"vercel-ai-gateway", "VERCEL_AI_GATEWAY_API_KEY", "https://ai-gateway.vercel.sh/v1", "typesafe-ai/jev"},
	}
	questions, specs := liveSpecs(t)
	for _, host := range hosts {
		t.Run(host.provider, func(t *testing.T) {
			key := os.Getenv(host.keyEnv)
			if key == "" {
				t.Skipf("set %s", host.keyEnv)
			}
			client := &openAICompatibleClient{provider: host.provider, baseURL: host.baseURL, apiKey: key}
			passed, total, inTok := 0, 0, 0
			var latencies []int
			for index, tc := range liveCases {
				state, _ := json.Marshal(tc.state)
				ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
				started := time.Now()
				resp, err := client.InvokeDecide(ctx, &DecideRequest{Model: "typesafe-ai/jev", State: state, Questions: questions},
					InvokeOptions{Provider: host.provider, UpstreamModel: host.upstream})
				cancel()
				if err != nil {
					t.Fatalf("case %d: hosted call failed: %v", index, err)
				}
				latencies = append(latencies, int(time.Since(started).Milliseconds()))
				if resp.InputTokens <= 0 {
					t.Errorf("case %d: no input tokens reported; billing would fall back to an estimate", index)
				}
				inTok += resp.InputTokens
				verified, err := decide.Verify(specs, resp.Answers)
				if err != nil {
					raw, _ := json.Marshal(resp.Answers)
					t.Fatalf("case %d: second pass rejected the hosted model's own output: %v\n%s", index, err, raw)
				}
				p, n, misses := tc.score(verified)
				passed, total = passed+p, total+n
				if len(misses) > 0 {
					t.Logf("case %d missed %v", index, misses)
				}
			}
			sort.Ints(latencies)
			t.Logf("RESULT %-38s valid=%d/%d judgment=%d/%d latency_ms(median=%d max=%d) tokens/decision(in=%d out=0 billed)",
				"typesafe-ai/jev@"+host.provider, len(liveCases), len(liveCases), passed, total,
				latencies[len(latencies)/2], latencies[len(latencies)-1], inTok/len(liveCases))
			if passed*100 < total*85 {
				t.Errorf("judgment %d/%d is below 85%%", passed, total)
			}
		})
	}
}

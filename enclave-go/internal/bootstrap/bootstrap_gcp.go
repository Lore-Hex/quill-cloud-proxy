//go:build cloud_gcp

// Package bootstrap: GCP Confidential Space variant.
//
// See bootstrap_aws.go for the per-cloud-file layout pattern this
// package follows. Each cloud has its own bootstrap_<cloud>.go with a
// matching `//go:build` tag; the linker picks one at compile time
// based on the `-tags cloud_<cloud>` build flag.
//
// Trust posture differs from the AWS variant in an important way:
//
// AWS:
//
//	The parent (a separate process on the EC2 host) reads the sealed
//	device blob from S3 + KMS-decrypts on behalf of the enclave, then
//	ships plaintext over vsock. The parent therefore *sees* the device
//	list and the Bedrock credentials in plaintext for ~ms at boot.
//	V1 trust caveat documented on the trust page.
//
// GCP:
//
//	The workload IS the only thing on the box (Confidential Space is a
//	single-container model — no sidecar, no parent). It calls Google
//	Secret Manager directly via the metadata-server-issued workload
//	identity token. The KMS attestation condition gates secret access
//	to "only an attested workload at the published image digest can
//	read this secret" — strictly stronger than the V1 AWS posture.
//
// Wire layout:
//  1. GET http://metadata.google.internal/computeMetadata/v1/instance/
//     service-accounts/default/identity?audience=...
//     → returns an OIDC ID token (NOT an access token; see attestation_gcp.go).
//  2. GET .../instance/service-accounts/default/token
//     → returns an access token usable as a Bearer.
//  3. GET https://secretmanager.googleapis.com/v1/projects/$PROJECT/
//     secrets/$NAME/versions/latest:access  Authorization: Bearer ...
//     → returns {"payload":{"data":"<base64>"}}
//
// Required env (set in the workload spec / Confidential Space metadata):
//
//	QUILL_GCP_PROJECT_ID         e.g. "quill-cloud-proxy"
//	QUILL_DEVICE_KEYS_SECRET     name of the secret holding the device-key JSON
//	QUILL_OPENROUTER_SECRET      name of the secret holding the OpenRouter API key (llm_openrouter builds)
//	QUILL_ANTHROPIC_SECRET       name of the secret holding the direct Anthropic API key (llm_anthropic builds)
//	QUILL_OPENAI_SECRET          name of the secret holding the OpenAI API key (llm_multi builds)
//	QUILL_GEMINI_SECRET          name of the secret holding the Gemini API key (llm_multi builds)
//	QUILL_CEREBRAS_SECRET        name of the secret holding the Cerebras API key (llm_multi builds)
//	QUILL_DEEPSEEK_SECRET        name of the secret holding the DeepSeek API key (llm_multi builds)
//	QUILL_MISTRAL_SECRET         name of the secret holding the Mistral API key (llm_multi builds)
//	QUILL_FIREWORKS_SECRET       name of the secret holding the Fireworks API key (llm_multi builds)
//	QUILL_FRIENDLI_SECRET        name of the secret holding the Friendli API key (llm_multi builds)
//	QUILL_BASETEN_SECRET         name of the secret holding the Baseten API key (llm_multi builds)
//	QUILL_WAFER_SECRET           name of the secret holding the Wafer API key (llm_multi builds)
//	QUILL_CRUSOE_SECRET          name of the secret holding the Crusoe API key (llm_multi builds)
//	QUILL_SYNTH_PANEL_PROMPT_SECRET           name of the secret holding the default synth panel prompt
//	QUILL_SYNTH_SYNTHESIS_PROMPT_SECRET       name of the secret holding the default synth synthesis prompt
//	QUILL_SYNTH_CODE_PANEL_PROMPT_SECRET      name of the secret holding the synth-code panel prompt
//	QUILL_SYNTH_CODE_SYNTHESIS_PROMPT_SECRET  name of the secret holding the synth-code synthesis prompt
//	QUILL_ADVISOR_WORKER_PROMPT_SECRET        name of the secret holding the advisor worker prompt
//	QUILL_ADVISOR_PROMPT_SECRET               name of the secret holding the advisor prompt
//	QUILL_TRUSTEDROUTER_INTERNAL_SECRET optional Secret Manager secret name
package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Lore-Hex/quill-cloud-proxy/enclave-go/internal/types"
)

const (
	metadataTokenURL  = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" // #nosec G101 -- metadata endpoint URL, not a secret.
	secretManagerHost = "secretmanager.googleapis.com"
)

// Fetch builds BootstrapData by pulling secrets from Google Secret
// Manager. Returns an error if the workload is missing the env vars
// (so a misconfigured deploy fails loudly instead of silently running
// with no devices).
func Fetch(ctx context.Context) (*types.BootstrapData, error) {
	project := os.Getenv("QUILL_GCP_PROJECT_ID")
	if project == "" {
		return nil, fmt.Errorf("bootstrap/gcp: QUILL_GCP_PROJECT_ID not set")
	}
	devicesSecret := os.Getenv("QUILL_DEVICE_KEYS_SECRET")
	if devicesSecret == "" {
		return nil, fmt.Errorf("bootstrap/gcp: QUILL_DEVICE_KEYS_SECRET not set")
	}
	// Each build target needs at least one provider secret set, but bootstrap
	// doesn't know which build it's serving — so we fetch whatever env vars
	// happen to be set. multi builds can set multiple at once; single-backend
	// builds set exactly one. Failing loud below if literally none are set.
	openrouterSecret := os.Getenv("QUILL_OPENROUTER_SECRET")
	anthropicSecret := os.Getenv("QUILL_ANTHROPIC_SECRET")
	openaiSecret := os.Getenv("QUILL_OPENAI_SECRET")
	geminiSecret := os.Getenv("QUILL_GEMINI_SECRET")
	cerebrasSecret := os.Getenv("QUILL_CEREBRAS_SECRET")
	deepseekSecret := os.Getenv("QUILL_DEEPSEEK_SECRET")
	mistralSecret := os.Getenv("QUILL_MISTRAL_SECRET")
	kimiSecret := os.Getenv("QUILL_KIMI_SECRET")
	zaiSecret := os.Getenv("QUILL_ZAI_SECRET")
	togetherSecret := os.Getenv("QUILL_TOGETHER_SECRET")
	fireworksSecret := os.Getenv("QUILL_FIREWORKS_SECRET")
	cohereSecret := os.Getenv("QUILL_COHERE_SECRET")
	voyageSecret := os.Getenv("QUILL_VOYAGE_SECRET")
	grokSecret := os.Getenv("QUILL_GROK_SECRET")
	novitaSecret := os.Getenv("QUILL_NOVITA_SECRET")
	phalaSecret := os.Getenv("QUILL_PHALA_SECRET")
	siliconflowSecret := os.Getenv("QUILL_SILICONFLOW_SECRET")
	tinfoilSecret := os.Getenv("QUILL_TINFOIL_SECRET")
	veniceSecret := os.Getenv("QUILL_VENICE_SECRET")
	// 2026-05-11 batch: parasail / lightning / gmi / deepinfra
	parasailSecret := os.Getenv("QUILL_PARASAIL_SECRET")
	lightningSecret := os.Getenv("QUILL_LIGHTNING_SECRET")
	gmiSecret := os.Getenv("QUILL_GMI_SECRET")
	deepinfraSecret := os.Getenv("QUILL_DEEPINFRA_SECRET")
	friendliSecret := os.Getenv("QUILL_FRIENDLI_SECRET")
	basetenSecret := os.Getenv("QUILL_BASETEN_SECRET")
	waferSecret := os.Getenv("QUILL_WAFER_SECRET")
	crusoeSecret := os.Getenv("QUILL_CRUSOE_SECRET")
	nebiusSecret := os.Getenv("QUILL_NEBIUS_SECRET")
	minimaxSecret := os.Getenv("QUILL_MINIMAX_SECRET")
	xiaomiSecret := os.Getenv("QUILL_XIAOMI_SECRET")
	synthPanelPromptSecret := os.Getenv("QUILL_SYNTH_PANEL_PROMPT_SECRET")
	synthSynthesisPromptSecret := os.Getenv("QUILL_SYNTH_SYNTHESIS_PROMPT_SECRET")
	synthCodePanelPromptSecret := os.Getenv("QUILL_SYNTH_CODE_PANEL_PROMPT_SECRET")
	synthCodeSynthesisPromptSecret := os.Getenv("QUILL_SYNTH_CODE_SYNTHESIS_PROMPT_SECRET")
	advisorWorkerPromptSecret := os.Getenv("QUILL_ADVISOR_WORKER_PROMPT_SECRET")
	advisorPromptSecret := os.Getenv("QUILL_ADVISOR_PROMPT_SECRET")
	if !anySet(
		openrouterSecret,
		anthropicSecret,
		openaiSecret,
		geminiSecret,
		cerebrasSecret,
		deepseekSecret,
		mistralSecret,
		kimiSecret,
		zaiSecret,
		togetherSecret,
		fireworksSecret,
		cohereSecret,
		voyageSecret,
		grokSecret,
		novitaSecret,
		phalaSecret,
		siliconflowSecret,
		tinfoilSecret,
		veniceSecret,
		parasailSecret,
		lightningSecret,
		gmiSecret,
		deepinfraSecret,
		friendliSecret,
		basetenSecret,
		waferSecret,
		crusoeSecret,
		nebiusSecret,
		minimaxSecret,
		xiaomiSecret,
	) {
		return nil, fmt.Errorf("bootstrap/gcp: at least one provider secret env must be set")
	}

	httpc := &http.Client{Timeout: 10 * time.Second}

	token, err := fetchAccessToken(ctx, httpc)
	if err != nil {
		return nil, err
	}

	devicesJSON, err := fetchSecret(ctx, httpc, token, project, devicesSecret)
	if err != nil {
		return nil, fmt.Errorf("bootstrap/gcp: device-keys: %w", err)
	}
	var devices []types.DeviceConfig
	if err := json.Unmarshal(devicesJSON, &devices); err != nil {
		return nil, fmt.Errorf("bootstrap/gcp: parse device-keys JSON: %w", err)
	}

	var openrouterKey []byte
	if openrouterSecret != "" {
		openrouterKey, err = fetchSecret(ctx, httpc, token, project, openrouterSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: openrouter key: %w", err)
		}
	}
	var anthropicKey []byte
	if anthropicSecret != "" {
		anthropicKey, err = fetchSecret(ctx, httpc, token, project, anthropicSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: anthropic key: %w", err)
		}
	}
	var openaiKey []byte
	if openaiSecret != "" {
		openaiKey, err = fetchSecret(ctx, httpc, token, project, openaiSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: openai key: %w", err)
		}
	}
	var geminiKey []byte
	if geminiSecret != "" {
		geminiKey, err = fetchSecret(ctx, httpc, token, project, geminiSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: gemini key: %w", err)
		}
	}
	var cerebrasKey []byte
	if cerebrasSecret != "" {
		cerebrasKey, err = fetchSecret(ctx, httpc, token, project, cerebrasSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: cerebras key: %w", err)
		}
	}
	var deepseekKey []byte
	if deepseekSecret != "" {
		deepseekKey, err = fetchSecret(ctx, httpc, token, project, deepseekSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: deepseek key: %w", err)
		}
	}
	var mistralKey []byte
	if mistralSecret != "" {
		mistralKey, err = fetchSecret(ctx, httpc, token, project, mistralSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: mistral key: %w", err)
		}
	}
	var kimiKey []byte
	if kimiSecret != "" {
		kimiKey, err = fetchSecret(ctx, httpc, token, project, kimiSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: kimi key: %w", err)
		}
	}
	var zaiKey []byte
	if zaiSecret != "" {
		zaiKey, err = fetchSecret(ctx, httpc, token, project, zaiSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: zai key: %w", err)
		}
	}
	var togetherKey []byte
	if togetherSecret != "" {
		togetherKey, err = fetchSecret(ctx, httpc, token, project, togetherSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: together key: %w", err)
		}
	}
	var fireworksKey []byte
	if fireworksSecret != "" {
		fireworksKey, err = fetchSecret(ctx, httpc, token, project, fireworksSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: fireworks key: %w", err)
		}
	}
	var cohereKey []byte
	if cohereSecret != "" {
		cohereKey, err = fetchSecret(ctx, httpc, token, project, cohereSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: cohere key: %w", err)
		}
	}
	var voyageKey []byte
	if voyageSecret != "" {
		voyageKey, err = fetchSecret(ctx, httpc, token, project, voyageSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: voyage key: %w", err)
		}
	}
	var grokKey []byte
	if grokSecret != "" {
		grokKey, err = fetchSecret(ctx, httpc, token, project, grokSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: grok key: %w", err)
		}
	}
	var novitaKey []byte
	if novitaSecret != "" {
		novitaKey, err = fetchSecret(ctx, httpc, token, project, novitaSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: novita key: %w", err)
		}
	}
	var phalaKey []byte
	if phalaSecret != "" {
		phalaKey, err = fetchSecret(ctx, httpc, token, project, phalaSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: phala key: %w", err)
		}
	}
	var siliconflowKey []byte
	if siliconflowSecret != "" {
		siliconflowKey, err = fetchSecret(ctx, httpc, token, project, siliconflowSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: siliconflow key: %w", err)
		}
	}
	var tinfoilKey []byte
	if tinfoilSecret != "" {
		tinfoilKey, err = fetchSecret(ctx, httpc, token, project, tinfoilSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: tinfoil key: %w", err)
		}
	}
	var veniceKey []byte
	if veniceSecret != "" {
		veniceKey, err = fetchSecret(ctx, httpc, token, project, veniceSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: venice key: %w", err)
		}
	}
	var parasailKey []byte
	if parasailSecret != "" {
		parasailKey, err = fetchSecret(ctx, httpc, token, project, parasailSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: parasail key: %w", err)
		}
	}
	var lightningKey []byte
	if lightningSecret != "" {
		lightningKey, err = fetchSecret(ctx, httpc, token, project, lightningSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: lightning key: %w", err)
		}
	}
	var gmiKey []byte
	if gmiSecret != "" {
		gmiKey, err = fetchSecret(ctx, httpc, token, project, gmiSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: gmi key: %w", err)
		}
	}
	var deepinfraKey []byte
	if deepinfraSecret != "" {
		deepinfraKey, err = fetchSecret(ctx, httpc, token, project, deepinfraSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: deepinfra key: %w", err)
		}
	}
	var friendliKey []byte
	if friendliSecret != "" {
		friendliKey, err = fetchSecret(ctx, httpc, token, project, friendliSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: friendli key: %w", err)
		}
	}
	var basetenKey []byte
	if basetenSecret != "" {
		basetenKey, err = fetchSecret(ctx, httpc, token, project, basetenSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: baseten key: %w", err)
		}
	}
	var waferKey []byte
	if waferSecret != "" {
		waferKey, err = fetchSecret(ctx, httpc, token, project, waferSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: wafer key: %w", err)
		}
	}
	var crusoeKey []byte
	if crusoeSecret != "" {
		crusoeKey, err = fetchSecret(ctx, httpc, token, project, crusoeSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: crusoe key: %w", err)
		}
	}
	var nebiusKey []byte
	if nebiusSecret != "" {
		nebiusKey, err = fetchSecret(ctx, httpc, token, project, nebiusSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: nebius key: %w", err)
		}
	}
	var minimaxKey []byte
	if minimaxSecret != "" {
		minimaxKey, err = fetchSecret(ctx, httpc, token, project, minimaxSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: minimax key: %w", err)
		}
	}
	var xiaomiKey []byte
	if xiaomiSecret != "" {
		xiaomiKey, err = fetchSecret(ctx, httpc, token, project, xiaomiSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: xiaomi key: %w", err)
		}
	}
	var synthPanelPrompt []byte
	if synthPanelPromptSecret != "" {
		synthPanelPrompt, err = fetchSecret(ctx, httpc, token, project, synthPanelPromptSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: synth panel prompt: %w", err)
		}
	}
	var synthSynthesisPrompt []byte
	if synthSynthesisPromptSecret != "" {
		synthSynthesisPrompt, err = fetchSecret(ctx, httpc, token, project, synthSynthesisPromptSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: synth synthesis prompt: %w", err)
		}
	}
	var synthCodePanelPrompt []byte
	if synthCodePanelPromptSecret != "" {
		synthCodePanelPrompt, err = fetchSecret(ctx, httpc, token, project, synthCodePanelPromptSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: synth-code panel prompt: %w", err)
		}
	}
	var synthCodeSynthesisPrompt []byte
	if synthCodeSynthesisPromptSecret != "" {
		synthCodeSynthesisPrompt, err = fetchSecret(ctx, httpc, token, project, synthCodeSynthesisPromptSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: synth-code synthesis prompt: %w", err)
		}
	}
	var advisorWorkerPrompt []byte
	if advisorWorkerPromptSecret != "" {
		advisorWorkerPrompt, err = fetchSecret(ctx, httpc, token, project, advisorWorkerPromptSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: advisor worker prompt: %w", err)
		}
	}
	var advisorPrompt []byte
	if advisorPromptSecret != "" {
		advisorPrompt, err = fetchSecret(ctx, httpc, token, project, advisorPromptSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: advisor prompt: %w", err)
		}
	}
	var internalGatewayToken string
	if internalSecret := os.Getenv("QUILL_TRUSTEDROUTER_INTERNAL_SECRET"); internalSecret != "" {
		value, err := fetchSecret(ctx, httpc, token, project, internalSecret)
		if err != nil {
			return nil, fmt.Errorf("bootstrap/gcp: trustedrouter internal token: %w", err)
		}
		internalGatewayToken = string(value)
	}

	return &types.BootstrapData{
		Devices:                    devices,
		Region:                     os.Getenv("QUILL_GCP_REGION"),
		OpenRouterAPIKey:           strings.TrimSpace(string(openrouterKey)),
		AnthropicAPIKey:            strings.TrimSpace(string(anthropicKey)),
		OpenAIAPIKey:               strings.TrimSpace(string(openaiKey)),
		GeminiAPIKey:               strings.TrimSpace(string(geminiKey)),
		CerebrasAPIKey:             strings.TrimSpace(string(cerebrasKey)),
		DeepSeekAPIKey:             strings.TrimSpace(string(deepseekKey)),
		MistralAPIKey:              strings.TrimSpace(string(mistralKey)),
		KimiAPIKey:                 strings.TrimSpace(string(kimiKey)),
		ZAIAPIKey:                  strings.TrimSpace(string(zaiKey)),
		TogetherAPIKey:             strings.TrimSpace(string(togetherKey)),
		FireworksAPIKey:            strings.TrimSpace(string(fireworksKey)),
		CohereAPIKey:               strings.TrimSpace(string(cohereKey)),
		VoyageAPIKey:               strings.TrimSpace(string(voyageKey)),
		GrokAPIKey:                 strings.TrimSpace(string(grokKey)),
		NovitaAPIKey:               strings.TrimSpace(string(novitaKey)),
		PhalaAPIKey:                strings.TrimSpace(string(phalaKey)),
		SiliconFlowAPIKey:          strings.TrimSpace(string(siliconflowKey)),
		TinfoilAPIKey:              strings.TrimSpace(string(tinfoilKey)),
		VeniceAPIKey:               strings.TrimSpace(string(veniceKey)),
		ParasailAPIKey:             strings.TrimSpace(string(parasailKey)),
		LightningAPIKey:            strings.TrimSpace(string(lightningKey)),
		GMIAPIKey:                  strings.TrimSpace(string(gmiKey)),
		DeepInfraAPIKey:            strings.TrimSpace(string(deepinfraKey)),
		FriendliAPIKey:             strings.TrimSpace(string(friendliKey)),
		BasetenAPIKey:              strings.TrimSpace(string(basetenKey)),
		WaferAPIKey:                strings.TrimSpace(string(waferKey)),
		CrusoeAPIKey:               strings.TrimSpace(string(crusoeKey)),
		NebiusAPIKey:               strings.TrimSpace(string(nebiusKey)),
		MiniMaxAPIKey:              strings.TrimSpace(string(minimaxKey)),
		XiaomiAPIKey:               strings.TrimSpace(string(xiaomiKey)),
		TrustedRouterBaseURL:       os.Getenv("TR_CONTROL_PLANE_BASE_URL"),
		TrustedRouterInternalToken: strings.TrimSpace(internalGatewayToken),
		SynthPanelPrompt:           strings.TrimSpace(string(synthPanelPrompt)),
		SynthSynthesisPrompt:       strings.TrimSpace(string(synthSynthesisPrompt)),
		SynthCodePanelPrompt:       strings.TrimSpace(string(synthCodePanelPrompt)),
		SynthCodeSynthesisPrompt:   strings.TrimSpace(string(synthCodeSynthesisPrompt)),
		AdvisorWorkerPrompt:        strings.TrimSpace(string(advisorWorkerPrompt)),
		AdvisorPrompt:              strings.TrimSpace(string(advisorPrompt)),
		// Legacy proxy fields unused on GCP — direct egress.
	}, nil
}

func anySet(values ...string) bool {
	for _, value := range values {
		if value != "" {
			return true
		}
	}
	return false
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func fetchAccessToken(ctx context.Context, c *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", metadataTokenURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("bootstrap/gcp: metadata token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return "", fmt.Errorf("bootstrap/gcp: read metadata token error body: %w", readErr)
		}
		return "", fmt.Errorf("bootstrap/gcp: metadata token http %d: %s", resp.StatusCode, body)
	}
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("bootstrap/gcp: decode token: %w", err)
	}
	return tr.AccessToken, nil
}

type secretResponse struct {
	Name    string `json:"name"`
	Payload struct {
		Data string `json:"data"` // base64-encoded
	} `json:"payload"`
}

func fetchSecret(ctx context.Context, c *http.Client, token, project, secretName string) ([]byte, error) {
	url := fmt.Sprintf(
		"https://%s/v1/projects/%s/secrets/%s/versions/latest:access",
		secretManagerHost, project, secretName,
	)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secret fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return nil, fmt.Errorf("secret fetch: read error body: %w", readErr)
		}
		return nil, fmt.Errorf("secret fetch http %d: %s", resp.StatusCode, body)
	}
	var sr secretResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(sr.Payload.Data)
	if err != nil {
		return nil, fmt.Errorf("base64 decode secret payload: %w", err)
	}
	return plaintext, nil
}

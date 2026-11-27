package trustedrouter

// Reviewed upstream routes at router catalog 89b9e58cc. Additions require a
// measured enclave release, not just a new control-plane catalog entry.
// The value permits BYOK in addition to managed credentials.
var confidentialRoutes = map[[3]string]bool{
	{"chutes", "deepseek/deepseek-v3.2", "deepseek-ai/DeepSeek-V3.2-TEE"}:                             true,
	{"chutes", "deepseek/deepseek-v4-flash-0731", "deepseek-ai/DeepSeek-V4-Flash-0731-TEE"}:           true,
	{"chutes", "google/gemma-4-31b-turbo", "google/gemma-4-31B-turbo-TEE"}:                            true,
	{"chutes", "moonshotai/kimi-k2.6", "moonshotai/Kimi-K2.6-TEE"}:                                    true,
	{"chutes", "moonshotai/kimi-k3", "moonshotai/Kimi-K3-TEE"}:                                        true,
	{"chutes", "qwen/qwen3.6-27b", "Qwen/Qwen3.6-27B-TEE"}:                                            true,
	{"chutes", "qwen/qwen3.8-27b", "Qwen/Qwen3.8-27B-TEE"}:                                            true,
	{"chutes", "z-ai/glm-5.1", "zai-org/GLM-5.1-TEE"}:                                                 true,
	{"chutes", "z-ai/glm-5.2", "zai-org/GLM-5.2-TEE"}:                                                 true,
	{"maple", "dealignai/deepseek-v4.1-flash-1017-uncensored", "deepseek-v4-1-flash-1017-uncensored"}: false,
	{"privatemode", "deepseek/deepseek-ocr-2", "deepseek-ocr-2"}:                                      false,
	{"privatemode", "mistralai/voxtral-mini-3b-2507", "voxtral-mini-3b"}:                              false,
	{"privatemode", "openai/gpt-oss-120b", "gpt-oss-120b"}:                                            false,
	{"privatemode", "openai/whisper-large-v3", "whisper-large-v3"}:                                    false,
	{"privatemode", "qwen/qwen3-embedding-4b", "qwen3-embedding-4b"}:                                  false,
	{"privatemode", "z-ai/glm-5.3", "glm-5.3"}:                                                        false,
	{"privatemode", "z-ai/glm-5.3-flash", "glm-5.3-flash"}:                                            false,
	{"tinfoil", "deepseek/deepseek-v4.1-flash", "deepseek-v4-1-flash"}:                                true,
	{"tinfoil", "deepseek/deepseek-v4.1-flash-1017", "deepseek-v4-1-flash"}:                           true,
	{"tinfoil", "google/gemma-4-31b-it", "gemma4-31b"}:                                                true,
	{"tinfoil", "meta-llama/llama-3.3-70b-instruct", "llama3-3-70b"}:                                  true,
	{"tinfoil", "mistralai/voxtral-4b-tts-2603", "voxtral-tts"}:                                       false,
	{"tinfoil", "mistralai/voxtral-small-24b", "voxtral-small-24b"}:                                   false,
	{"tinfoil", "moonshotai/kimi-k3.1-pro", "kimi-k3-1-pro"}:                                          true,
	{"tinfoil", "nomic-ai/nomic-embed-text", "nomic-embed-text"}:                                      true,
	{"tinfoil", "openai/gpt-oss-120b", "gpt-oss-120b"}:                                                true,
	{"tinfoil", "openai/gpt-oss-safeguard-120b", "gpt-oss-safeguard-120b"}:                            true,
	{"tinfoil", "openai/whisper-large-v3-turbo", "whisper-large-v3-turbo"}:                            false,
	{"tinfoil", "qwen/qwen3-tts", "qwen3-tts"}:                                                        false,
	{"tinfoil", "z-ai/glm-5.3", "glm-5-3"}:                                                            true,
}

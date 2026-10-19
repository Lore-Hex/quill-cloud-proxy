# Amazon Bedrock

The `amazon-bedrock` provider uses only the regional Mantle endpoint
`https://bedrock-mantle.us-east-1.api.aws/v1`. It is Credits-only and Standard
privacy, not ZDR or confidential inference. Runtime, global and premium-tier
prices must never be substituted for this endpoint's exact standard-tier SKUs.

## Credential

The dedicated IAM user `trustedrouter-bedrock-inference` has only discovery and
inference permissions restricted to `us-east-1`. It has no AWS access key,
console password, administrative permissions, or Marketplace subscription rights.
The service-specific key is stored as `BEDROCK_API_KEY` in the operator's private
keyfile, and independently as `trustedrouter-bedrock-api-key` in each cloud.
Never put its value in this repository or logs.

The October 19 key expires **January 17, 2027 at 08:16:24 UTC**. Rotate by
December 18, 2026. Create a replacement service credential for the same scoped
user, verify discovery plus streaming/non-streaming PONG, publish independent
cloud-local copies, and complete all regional rolls before retiring the old
credential. Longer-term production hardening should use short-lived federation
instead of granting an enclave permission to issue its own long-lived keys.

## Release Order

1. GCP Secret Manager version 1 and AWS Secrets Manager `quill/` copies in
   eu-west-1 and eu-west-3 are staged. Refresh uses the per-secret tr-deploy
   accessor; GCP inference uses the existing quill-workload accessor.
2. Azure's new sealed bundle is **f2d126c744894b7fa48f2f2d89c9a655**. Its 78
   names preserve the previous 77 entries plus Bedrock. The earlier staging
   version `c01ab73ec75340ec9f5152446fae3c18` is incomplete; do not deploy it.
   Pin the complete version and use the generated `tools/azure-bundle.manifest`.
   Preserve the existing Privatemode, Telluvian and both Decision Models envs.
3. Merge only after CI, then use the guarded GCP gateway workflow. Verify every
   region's health, image measurement and billing before publishing CP routes.
4. Follow the AWS enclave release and Azure enclave runbooks, holding the shared
   rollout reservation across all phases. AWS also needs the new Mantle vsock
   tunnel at port 8116. Azure must rebind SKR for the newly measured bundle pin.
   Uploading secrets alone does not upgrade either gateway.
5. The CP Bedrock admission hold remains in AWS/Azure until those gateways pass
   verification. Remove each hold only with release evidence; never advertise
   routes from an upgraded CP against an older gateway.

The hourly parser discovers new models, joins exact AWS price SKUs, and requires
a usage-bearing canary for admission. Initial dedicated-key verification passed
34 models. Missing prices, unsupported routes and transcription-contract
collisions remain held. No cross-provider alias or price fallback is permitted.

Official references: [Mantle endpoints](https://docs.aws.amazon.com/bedrock/latest/userguide/endpoints.html),
[AWS API keys](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-generate.html).

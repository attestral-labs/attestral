# Vertex AI agent-runtime hardening fixture (GCP)

The GCP half of the AI-cloud agent-runtime moat: the Vertex AI reasoning engine
(Agent Engine) and the endpoint it serves through. Each `_weak` resource omits
the customer-managed encryption key; the `_hardened` counterpart sets one and
stays silent.

```bash
attestral scan examples/vertex-ai-hardening
```

```
4 components · 2 findings · 2 medium
```

- `google_vertex_ai_reasoning_engine.shipping_weak` - no
  `encryption_spec.kms_key_name`, so the agent runtime's data is under a
  Google-managed key you cannot scope or revoke. Fires **ATL-435**.
- `google_vertex_ai_endpoint.serving_weak` - no `encryption_spec.kms_key_name` on
  the model-serving surface an agent calls. Fires **ATL-436**.

Vertex has no public-network flag analogous to Bedrock's `network_mode` (access
is governed by IAM, the service account, and Private Service Connect), so the
clean static signal here is the missing customer-managed key.

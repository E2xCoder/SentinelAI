# Prompt-injection corpus

`cases.yaml` holds attacker-controlled log strings (`id`, `description`, `payload`) that try to hijack the LLM triage step.
Non-printable and non-ASCII characters are YAML escapes on purpose; load the file with `yaml.safe_load`.
`attack_auth.log` is a 12-line sshd brute force (documentation IPs only) that embeds several payloads in usernames and trailing text.
It is consumed by `tests/test_triage_injection.py`, which checks the prompt, the validator and the response path.
This directory is separate from `benchmarks/scenarios/`; it is not part of `MANIFEST.sha256` or `baseline.json`.

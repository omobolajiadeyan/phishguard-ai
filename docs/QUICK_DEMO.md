# One-Minute PhishGuard Demo

This demo uses only synthetic or reserved-domain input. PhishGuard runs
offline and does not send the input to a remote service.

## 1. Install

```bash
python -m pip install \
  https://github.com/omobolajiadeyan/phishguard-ai/releases/download/v0.4.0/phishguard_ai-0.4.0-py3-none-any.whl
```

## 2. Compare a Legitimate and Suspicious URL

```bash
phishguard url "https://www.example.com/account"
phishguard url "http://192.0.2.10/secure-login/verify" --verbose --plain
```

The second command uses the documentation-only `192.0.2.0/24` address range.
The verbose output shows which explainable features contribute to the score.

## 3. Export Findings

```bash
phishguard url "http://192.0.2.10/secure-login/verify" \
  --output finding.json \
  --plain
```

For GitHub Code Scanning and CI usage, follow the
[SARIF integration guide](GITHUB_CODE_SCANNING.md).

## Development Preview: Email Authentication Results

SPF, DKIM, and DMARC analysis is merged to `main` but is not included in the
v0.4.0 wheel. Install the current source before trying this preview:

```bash
git clone https://github.com/omobolajiadeyan/phishguard-ai.git
cd phishguard-ai
python -m pip install --editable .
```

Then analyze a synthetic header value:

```bash
phishguard email \
  --subject "Security alert" \
  --body "Click here to verify your account." \
  --authentication-results "mx.example; spf=fail; dkim=fail; dmarc=fail" \
  --verbose \
  --plain
```

Authentication failures are supporting signals. PhishGuard does not validate
DNS policy or cryptographic signatures, and callers must provide the final
trusted receiver's `Authentication-Results` value.

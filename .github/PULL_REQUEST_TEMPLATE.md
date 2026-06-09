## Summary

- 
- Related issue:
- [ ] A maintainer confirmed the implementation approach on the issue.

## Verification

- [ ] `python -m unittest discover -s tests -v`
- [ ] `python -m py_compile email_auth.py features.py model.py phishguard.py reporting.py`
- [ ] `python tools/repository_policy.py`
- [ ] I tested the relevant CLI or library behavior directly.
- [ ] I updated documentation for user-facing behavior changes.
- [ ] Detection changes include legitimate and malicious regression samples.
- [ ] No credentials, personal data, or active malicious payloads are included.
- [ ] No executables, binaries, symlinks, obfuscated payloads, or unexpected
      dependencies are included.

## Accuracy Impact

Describe any changed probabilities, verdicts, thresholds, or false-positive
tradeoffs. Write `No scoring change` when this does not apply.

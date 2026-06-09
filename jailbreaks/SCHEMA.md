# Jailbreak payload schema

This repository ships **without** live jailbreak payloads, by design. The
harness, detector, judge, probes, and reporting are public; the attack
techniques are withheld to avoid abuse.

The tool runs fine without payloads: it executes the **control baseline** only
(a plain request with no attack), which validates that a planted rule is
actually enforced.

## Adding your own techniques

Create `jailbreaks/payloads_local.py` (gitignored). Define a list named
`PRIVATE_JAILBREAKS` of `core.models.Jailbreak` objects:

```python
from core.models import Jailbreak

PRIVATE_JAILBREAKS = [
    Jailbreak(
        id="my-technique-1",
        name="Human-readable name",
        technique="technique_family",
        description="What it does and what it tests.",
        template="...{benign_request}...",
    ),
]
```

### Field reference

| Field | Purpose |
|-------|---------|
| `id` | Unique identifier, used in reports and `--filter`. |
| `name` | Human-readable label. |
| `technique` | Family name; results are averaged per technique. |
| `description` | What the technique does / probes. |
| `template` | The payload. Must contain `{benign_request}`, filled at runtime with a probe-specific benign ask. |

### Scope

Templates test robustness against **benign planted rules** only (keep a codeword
secret, avoid a word, stay in a language). They contain no request for harmful
content. Run only against systems you own or are authorized to test.

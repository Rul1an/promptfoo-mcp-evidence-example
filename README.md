# Small MCP gate example — retained-evidence check

A small worked example related to [Promptfoo #11683](https://github.com/promptfoo/promptfoo/issues/11683).

The useful distinction is between a successful tool response and enough evidence to accept a task.
This example uses Promptfoo 0.124.1's native MCP provider, Assay CLI and MCP server 6.12.0,
and a local synthetic receiver. It does not implement CIGE or require a new Promptfoo provider.

| Control | Provider | Gate | Local receiver | Required receipt | Task accepted |
|---|---|---|---|---|---|
| C1 declared target | success | allow | arrived | present | yes |
| C2 undeclared target | error -31999 | deny | absent | absent | no |
| C3 declared target, receipt suppressed | success | allow | arrived | absent | no |

C1 is the healthy-receiver control for C2. C3's missing receipt is deliberately synthetic.
Two further controls retain a preflight refusal for an unsupported mandatory constraint (C4),
and a one-byte bundle mutation rejected by the recorded Assay verifiers (C5).
The unsupported-constraint refusal belongs to our harness, not Assay's policy loader.

## Check offline

Use Python 3; no installation, network, Docker, model or Assay binary is needed:

```sh
python3 -I independent_reproducer.py
```

Expected: exit 0 and `all_reproduced: true`. This recomputes classifications and archive hashes
from retained data. It does **not** execute Promptfoo, the gate, or the Assay verifiers again.
In particular, C4's directory contents show retained preflight output, not an independent proof
that no process ran; the original harness's launch-spy test supplied that separate observation.
C5 verifier exit codes and diagnostics are recorded observations, not fresh executions.

The reader is copied byte-for-byte from the reviewed probe. `MANIFEST.json` records original and
packaged hashes and transformations. Promptfoo rows retain only description, success and error;
verifier logs retain exit/stdout/stderr with the original absolute attempt path replaced by
`<retained-attempt>`. These are explicitly derived projections, not original
raw exports. Other listed files are byte-identical. Original source hashes are provenance references; the unpublished source files are not included
for independent comparison. Hashes bind bytes, not authorship or trustworthy execution.

## Limits

This is one local fixture and one retained attempt. No real GitHub operation, model behaviour,
production integration, CIGE conformance or general guardrail support is demonstrated.
The original probe used sampled resource checks, not continuous resource enforcement.
The selected successful attempt does not replace the two failed development attempts retained
in the private experiment. This is an evidence-reading example, not a clean-room runtime reproduction.

## Provenance and authorship

Execution versions: Promptfoo 0.124.1, Node 24.19.0, Assay CLI and MCP server 6.12.0, macOS arm64.
This is not a 6.14.1 execution claim. The reader and synthetic records were prepared by Roel Schuurkes
with AI assistance for implementation and review. Roel maintains Assay and is responsible for this example.

This package contains selected retained evidence, not the full runtime harness. No Promptfoo or Assay
installation is needed for the offline check. SHA-256 values and declared transformations are in MANIFEST.json.

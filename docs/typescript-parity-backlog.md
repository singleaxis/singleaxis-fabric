# TypeScript recorder parity

The Python and TypeScript packages share the recorder goal but need not expose
identical language syntax. Release parity means both packages can emit the
documented recorder metadata safely and their published package surfaces do not
contain control, assurance, or governance implementations.

Current release gates cover:

- decision, model, tool, retrieval, memory, side-effect, delegation, failure,
  retry, file, hook, skill, and generic interaction metadata;
- SHA-256 validation for caller-supplied hash fields;
- hash-by-default behavior for sensitive targets and file paths;
- lint, type checking, build, unit tests, and exact packed-package inspection;
  and
- trace/span identity compatibility with Fabric Node.

Future parity work must be added as a small recorder feature with cross-SDK
tests. Policy decisions, judge execution, red-team orchestration, prompt-time
PII controls, and management APIs are deliberately outside this backlog.

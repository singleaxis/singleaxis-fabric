# Publication transformations

This publication copy replaces the temporary benchmark virtual-environment
absolute path prefix in stack traces and recorded commands with
`<BENCHMARK_VENV>`. No workspace or user-home paths were found. This is an
evidence-presentation transformation only: measurements, statuses, workload,
source hashes and benchmark/runtime code are unchanged. Original unmodified
campaign output remains outside this publication copy.

All requests and recorded content use a synthetic loopback fixture. API-key
placeholders and privacy canaries are synthetic, never live credentials.
`artifact-sha256.json` fingerprints these publication bytes; source hashes in
metrics continue to describe the originally executed Python source files.

## Source publication completeness

The supplied source archive omits 63 subprocess `stderr.log` diagnostics
listed in the original hash index at the initial PR commit. The current
`artifact-sha256.json` includes only the 324 available artifacts. Original hashes
are retained in `omitted-artifacts.json`; those bytes were not recovered or
reconstructed during PR publication. All 323 frozen artifacts other than this publication note remain unchanged.
The current note hash is refreshed in the index. This is a partial diagnostic inventory,
not a claim that every original campaign file is available in this source.
The benchmark measurements and raw record/truth files remain unchanged.
The original 387-entry index remains available at the initial PR commit;
only its publication inventory was corrected in this follow-up. The published measurements apply to the frozen runtime
at initial PR commit `18ec69a4ddd6e5fdab7a097b30b34571096e708f`; later CI
follow-up changes do not constitute a new matched benchmark campaign.

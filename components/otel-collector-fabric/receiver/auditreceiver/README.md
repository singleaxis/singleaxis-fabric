# auditd receiver: durable logfile replay

This receiver observes configured Linux audit metadata. It does not establish
complete host coverage or semantic agent intent. Native audit rules/kernel
qualification remains a separate deployment gate.

## Migration and configuration

`source: logfile` now **requires** an absolute `state_directory`. There is no
silent in-memory fallback. Existing logfile deployments must create a dedicated
0700 directory owned by the collector user and mount it read-write on persistent
local storage. Keep the audit source directory read-only. Do not share one state
directory between receivers or reuse it for a different `log_path`.
`source: netlink` remains valid without this setting and remains live/nonreplayable.

```yaml
receivers:
  audit:
    source: logfile
    log_path: /var/log/audit/audit.log
    state_directory: /var/lib/fabric/audit
    max_state_bytes: 16777216
    max_batch_bytes: 4194304
    max_record_bytes: 1048576
    max_batch_records: 4096
    assembly_timeout: 500ms
    max_events_per_sec: 200
    hash_file_paths: true
```

State holds scrubbed metadata, not raw audit lines/argv/file paths. It still
contains potentially sensitive process/user/peer metadata; protect the volume
and backups accordingly. State is integrity-checked with SHA-256, not encrypted
or authenticated against an operator who controls the volume.

## Delivery and identity

One checkpoint contains the accepted `(device/inode, generation, byte offset,
256-byte suffix hash, oversized-line discard state)` and at most one pending
scrubbed OTLP batch. The receiver writes and fsyncs a temporary checkpoint,
atomically renames it, and fsyncs the directory **before** calling `ConsumeLogs`.
It commits the candidate cursor only after downstream acceptance. Every error,
including a permanent downstream rejection, retains that batch and pauses
source reads. Replay decodes a fresh copy, so mutating consumers cannot change
the retained payload. Checkpoint-write failures also retain the old accepted
cursor and produce rate-limited source-health warnings.

Delivery is **at least once**. A crash between downstream acceptance and the
checkpoint commit replays the exact staged payload. `fabric.record_id` (64-hex
SHA-256) remains unchanged for that retry; destinations should deduplicate by
this ID. The source ID is a random 32-hex identity persisted with this state.
Generation, source inode, input offset and audit event identity distinguish
observations. Deleting/reinitializing state creates a different identity and
can replay already accepted observations. Backups must be restored consistently;
there is no external anti-rollback ledger.

Acceptance means the next Collector consumer accepted the batch, not that a
remote destination durably stored it. Use and qualify a durable downstream
queue/exporter and destination acknowledgement separately.

Durable logfile mode does not temporally collapse distinct observed events.
`dedupe_window` applies only to netlink. `max_events_per_sec` paces accepted
logfile batches instead of dropping records (a batch may arrive as a burst).

## Bounds and evidence

- Input memory is bounded by `max_record_bytes`, `max_batch_bytes` and
  `max_batch_records`, plus parsed/OTLP representation overhead. A batch stops
  before its byte budget would require splitting an otherwise valid record.
- Oversized lines are consumed in bounded fragments. Discard continuation is
  checkpointed so restart does not parse the remainder as a new valid record.
  `audit.oversized_records` counts the line once; `audit.discarded_bytes` accounts
  for each acknowledged discarded fragment, including fragments before newline.
- A batch emits `audit.event=logfile_checkpoint` with input, invalid, oversized,
  filtered, incomplete, unmatched and discarded-byte counters. Input count is
  source-record starts in the batch; a discard-only continuation may be zero.
  Invalid syntax is not silently parsed as serial zero. Filtered events are
  intentionally excluded by class/key; unmatched fragments have a separate
  counter. Incomplete assembled events carry `audit.assembly_complete=false`.
  Batch/time limits may split a multi-record event; later unmatched records are
  counted. This bounded assembly is not a claim of complete argv/path evidence.
- Disk contains one checkpoint, a lock, and at most one atomic-write temporary
  file: provision at least **twice `max_state_bytes`**, plus filesystem overhead.
  State quota/disk-full/permission errors pause without cursor advance; very
  metadata-dense batches may require a larger state cap or smaller batch cap.
  Corrupt, oversized, wrong-source or unsupported-version checkpoints fail
  startup and are never automatically reset. Preserve them for recovery.
- Defaults: state 16 MiB, batch 4 MiB, record 1 MiB, 4096 source fragments/batch.
  Config bounds: record 4 KiB–16 MiB; batch >= record and <=64 MiB; state >=2×batch
  and <=256 MiB; fragments 1–65536. These are bounded receiver state/working sets,
  not quotas on auditd's source files, collector logs, or remote storage.

## Rotation and limitations

The receiver drains its retained descriptor. On restart it can find the saved
inode in the configured source or at most 128 sibling directory entries. For
numeric `audit.log.N` rename rotation, it walks retained successor suffixes
toward the active file, revalidating inode mappings. It does not infer ordering
from mtimes or inode numbers. Missing numeric successors, unsupported/compressed
names, exhausted inventory or ambiguous ordering emit `source_rotation_gap`;
a missing saved source emits `source_missing`. These incidents have unknown
missing-event totals, never fabricated exact counts. A proven adjacent numeric
transition emits `source_rotated`, which still does not guarantee auditd/kernel
completeness or rule coverage.

The source offset and original observed-byte suffix detect truncation and
copytruncate-regrow near the cursor. Consumed ranges are revalidated before
staging; detected concurrent mutation emits `source_truncated_or_rewritten`
before restarting at offset zero in a new generation. A suffix hash cannot
detect arbitrary rewriting solely before that suffix, restore of identical
bytes, or source events removed before observation. Retain uncompressed numeric
rotations long enough for the slowest outage/replay window. Files not durably
staged still depend on the original source surviving a crash. The receiver
never changes audit rules to apply backpressure.

Source files must be regular nonsymlink files; nonblocking open rejects FIFOs
without trapping shutdown. The state directory is single-owner locked. Shutdown
honors its context or a five-second bound; a misbehaving downstream consumer
may continue holding the state lock until it returns. The stored replay remains
intact; do not start a second writer or delete the lock/state to bypass it.

## Local verification

`go test -race ./...` covers temporary-file replay/restart, failed acceptance,
pre-rename faults, ambiguous acceptance replay, mutating/permanent-error consumers,
numeric multi-rotation, copytruncate/regrow and concurrent rewrite, missing
sources, corruption/quota/locking, discard continuation, hostile argc/header and
rotation suffixes, FIFO rejection, and bounded shutdown. Fabricguard's tests
verify typed IDs/cursors/loss counters and closed statuses survive protection.
These local tests do not constitute live auditd/kernel/container qualification.


Native netlink decoding validates message boundaries and truncation before
turning kernel payloads into parser input. Rule construction uses native amd64
or arm64 syscall numbers with an explicit architecture equality filter;
unknown/32-bit compatibility ABIs are excluded from translation. Local framing
and wire-layout tests do not qualify live kernel collection or rule management.

Netlink assembly retains at most 256 records per pending serial. Excess records
produce `assembly_records_dropped` with a record count, independently of event
evictions. Control queries use a separate non-multicast socket and match kernel
responses by sequence and type, with bounded receive time and message count.

# Velociraptor Integration — Future Improvements

This document captures improvements identified during end-to-end system testing
of the Velociraptor integration (branch `feat/velociraptor-integration`).

All items were discovered through real investigation testing against a live
Velociraptor server and Elasticsearch cluster with 37,476 Windows Security events.

---

## 1. Timeline Extraction for Velociraptor Artefacts

**Priority:** High
**Effort:** Medium

### Problem

`build_unified_timeline` always returns empty for Velociraptor data. The timeline
extractor (`SmartExtractor.extract_timeline_events`) expects raw Elasticsearch events
with `@timestamp` and `event.code` fields. Velociraptor artefacts use different
field names (e.g. `CreatedTime`, `LastRunTimes`, `ModificationTime`).

### Proposed Fix

Add `extract_timeline_events_from_velociraptor()` to `SmartExtractor` that maps
Velociraptor-specific timestamp fields:

- `CreatedTime` (from Pslist)
- `LastRunTimes` (from Prefetch — array of timestamps)
- `ModificationTime` (from ShimCache)
- `LastExecution` (from UserAssist)
- `LastWriteTime` (from RecentDocs)
- `Mtime` (from Scheduled Tasks)
- `Created` (from Services)

Each Velociraptor tool invocation should produce timeline events with the
artefact name as the `event_type`, enabling a unified timeline across SIEM
events and endpoint forensic artefacts.

### Acceptance Criteria

- `build_unified_timeline` returns events from Velociraptor after `velociraptor_prefetch`
- Timeline events are sorted chronologically alongside SIEM events
- Each event shows source (`velociraptor`), artefact type, and host

---

## 2. Field Mapping Normalisation for SIEM IoC Extraction

**Priority:** High
**Effort:** Medium

### Problem

The IoC extractor in `SmartExtractor._extract_from_event()` expects ECS-standard
field names (`source.ip`, `user.name`, `process.name`, etc.). However:

- `smart_search` returns compact summaries with fields like `code`, `name`, `message`
  — these don't match the extractor's expected field paths
- Older Winlogbeat indices may use flat field names rather than nested ECS structures
- `threat_hunt_search` extracts IoCs from aggregations, not individual events,
  so the per-event extractor misses most indicators

### Proposed Fix

1. Extend `_extract_from_event()` field lists to include common non-ECS variants:
   - `code` → treat as `event.code`
   - `name` → treat as `host.name`
   - `message` → regex-extract IPs, usernames, process names from the message body

2. Add a `_extract_iocs_from_message()` method that parses unstructured Windows
   Security event messages using regex patterns for:
   - IP addresses (from "Source Network Address" fields in the message)
   - Account names (from "Account Name" fields)
   - Process names (from "New Process Name" fields)

3. Consider making `threat_hunt_search` return its aggregation-based IoCs in a
   format that `auto_capture` can consume directly, rather than relying on
   per-event extraction.

### Acceptance Criteria

- `smart_search` for Event 4672 auto-captures at least usernames and hostnames
- `threat_hunt_search` IoCs are captured into the investigation state
- Works with both ECS and legacy Winlogbeat field formats

---

## 3. Cross-Correlation Tool Enhancements

**Priority:** Medium
**Effort:** Medium

### Problem

`correlate_siem_with_endpoint` currently only correlates processes, IPs, and
services. It does not correlate:

- File hashes (Amcache SHA1 → SIEM file hash events)
- Scheduled tasks (VR task names → SIEM Event 4698)
- User accounts (VR user list → SIEM logon events)

Additionally, `endpoint_to_siem_pivot` returns IoCs for manual follow-up rather
than automatically searching SIEM. The investigator must manually call
`hunt_for_ioc` for each extracted IoC.

### Proposed Fix

1. Add hash, scheduled task, and user correlation to `correlate_siem_with_endpoint`
2. Make `endpoint_to_siem_pivot` optionally auto-search SIEM for extracted IoCs
   (pass the `SearchClient` to the tool so it can run ES queries directly)
3. Add a `correlate_by_time` tool that takes a time window and cross-references
   SIEM events with Velociraptor artefact timestamps to find co-occurring activity

### Acceptance Criteria

- `correlate_siem_with_endpoint` checks hashes and users alongside processes/IPs
- `endpoint_to_siem_pivot` with `auto_search=True` returns SIEM matches directly

---

## 4. Velociraptor Collection Performance

**Priority:** Low
**Effort:** Low

### Problem

Velociraptor real-time collections (`collect_realtime`) take ~47 seconds for
`Linux.Sys.Pslist` on a non-privileged agent. This is inherent to the gRPC
`watch_monitoring` approach which waits for `System.Flow.Completion`.

For the async path (`collect_artifact` + `get_collection_results`), the default
timeout of 5 minutes (10 retries × 30 seconds) is appropriate but the retry
delay is coarse — a flow that completes in 48 seconds wastes 12 seconds waiting
for the next poll.

### Proposed Fix

1. Implement exponential backoff for `get_collection_results`: start with 5s
   retry, increase to 10s, 20s, 30s — this catches fast completions sooner
2. Add progress logging during polling so the user sees
   `[polling] Flow F.xxx: IN_PROGRESS (attempt 3/10)` rather than silence
3. For the real-time path, consider adding a configurable timeout parameter to
   `collect_realtime` so investigators can abort long-running collections

### Acceptance Criteria

- Collections that complete in <10s are returned within 15s (not 30s)
- Polling progress is visible via MCP server logs

---

## 5. Windows Artefact Coverage

**Priority:** Medium
**Effort:** Low

### Problem

The current Velociraptor integration covers the most common forensic artefacts
but is missing several that are valuable for Windows IR:

- `Windows.EventLogs.Evtx` — direct event log collection
- `Windows.Forensics.SRUM` — System Resource Usage Monitor
- `Windows.Forensics.Lnk` — LNK file analysis (program execution)
- `Windows.Registry.Run` — Registry Run keys (persistence)
- `Windows.System.DLLs` — loaded DLLs (injection detection)
- `Windows.Detection.BinaryRename` — renamed system binaries

### Proposed Fix

Add dedicated tools for the most impactful missing artefacts, or extend
`velociraptor_collect_artifact` with preset parameter templates so investigators
can collect these without knowing the exact artefact names and parameters.

### Acceptance Criteria

- At least `Registry.Run` and `Forensics.Lnk` have dedicated tools
- `velociraptor_list_artifacts` output includes usage recommendations

---

## 6. Investigation Index Synchronisation

**Priority:** Medium
**Effort:** Low

### Problem

The master investigation index (`index.json`) shows `ioc_count=0` for
investigations that actually contain hundreds of IoCs on disc. The `add_findings`
method updates the investigation files but does not update the index entry's
`ioc_count` or `sources` fields.

This causes `list_investigations` to show inaccurate IoC counts, though
`get_shared_iocs` still works correctly because it loads full investigation
data from disc.

### Proposed Fix

After `save_state()` in `add_findings`, call
`self.storage.index.add_investigation(investigation.manifest)` and
`self.storage._save_index()` to keep the index in sync.

### Acceptance Criteria

- `list_investigations` shows accurate `ioc_count` after auto-capture
- Index `sources` field includes all contributing tool names

---

## 7. MISP Integration for Velociraptor IoCs

**Priority:** Low
**Effort:** Medium

### Problem

The existing MISP export (`export_to_misp`) works for manually added IoCs but
has not been tested with auto-captured Velociraptor IoCs. The IoC format from
Velociraptor (process names, command lines, file paths) may not map cleanly to
MISP attribute types.

### Proposed Fix

1. Test MISP export with a Velociraptor-enriched investigation
2. Add MISP attribute type mappings for Velociraptor-specific IoC types
   (e.g. `IoCType.COMMANDLINE` → MISP `text` attribute with `comment` context)
3. Add a `velociraptor` tag to MISP events so analysts know the source

### Acceptance Criteria

- `export_to_misp` produces valid MISP JSON for investigations with VR IoCs
- MISP event includes source attribution for each IoC

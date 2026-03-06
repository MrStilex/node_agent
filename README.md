# Node-Agent Payload Contract

## Purpose
This document defines the strict telemetry contract between `node-agent` and Collector for Remnawave/Xray monitoring.

## Protocol Versioning
Every event MUST include:

```json
"schema_version": "1.0"
```

Rules:
- `1.x`: additive-compatible changes only (new optional fields, new enum values only if Collector allows them).
- `2.0+`: breaking changes (rename/remove/type changes) allowed only with coordinated Collector + UI rollout.
- Collector MUST reject events with missing `schema_version`.

## Transport Envelope
Agent sends batches to Collector as:

```json
{
  "events": [
    { "schema_version": "1.0", "event_type": "...", "...": "..." }
  ]
}
```

Schema:
- `contracts/collector_ingest.schema.json`

## Event Types
Supported `event_type` values:
- `node_heartbeat`
- `node_summary`
- `fail_event`
- `reconnect_suspect`
- `node_incident`

Master event schema:
- `contracts/event.schema.json`

## Event Schemas
- `contracts/node_heartbeat.schema.json`
- `contracts/node_summary.schema.json`
- `contracts/fail_event.schema.json`
- `contracts/reconnect_suspect.schema.json`
- `contracts/node_incident.schema.json`

## Semantics Notes
- Raw log lines MUST NOT be sent as standalone events.
- `received request` and `connection opened` MUST be filtered and never emitted.
- `fail_event` MUST be aggregated by windows (`window_start/window_end`) and deduplicated.
- `fail_event.affected_scope` semantics:
  - `user`: at least one correlated email
  - `ip`: no email, but at least one source IP
  - `node`: no user/IP binding
- `node_summary.route_split` is mandatory and used by analytics/UI for route health.

## Required Compatibility for UI/Collector
Collector and Telegram UI rely on these fields and MUST treat them as contract-critical:
- `schema_version`, `event_type`, `node_id`
- All required fields from the corresponding JSON Schema
- `fail_event.fingerprint`
- `node_incident.fingerprint`

## Validation Recommendation
Collector should validate each incoming event against `contracts/event.schema.json` and reject invalid payloads with explicit error details.

## Current Contract Version
- `schema_version`: `1.0`

# Filebeat

Not used: workers push events straight to Redis lists consumed by Logstash (docs/ingestion.md),
which avoids filesystem coupling and buffers during outages. If an external tool can only write
JSONL files, ship them with Filebeat to a Logstash `beats` input and emit the unified event schema
(at minimum `bb.index`, `event.kind`, `event.type`, `@timestamp`).

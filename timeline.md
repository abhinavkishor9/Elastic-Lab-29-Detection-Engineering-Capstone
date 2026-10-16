# Investigation Timeline — Lab 29: Detection Engineering Capstone

## 16 October 2026 — Detection Development and Validation

| Stage | Activity | Evidence or result |
|---|---|---|
| 1 | Defined the detection hypothesis | Identify PowerShell process-creation events containing encoded-command or hidden-window indicators |
| 2 | Queried the baseline telemetry | Approximately 52,000 documents processed |
| 3 | Reviewed the baseline aggregation | 51,901 records in the primary group for `desktop-9mmm37v`, provider `Microsoft-Windows-Sysmon`, dataset `windows.sysmon_operational` |
| 4 | Executed the initial detection query | Zero matching results |
| 5 | Executed a benign PowerShell baseline command | Expected message displayed in the local console |
| 6 | Executed an encoded PowerShell test | Harmless encoded instruction executed and displayed its expected output |
| 7 | Executed a hidden-window PowerShell test | Command returned without visible output in the console |
| 8 | Repeated the detection query | Zero matching results remained visible in the supplied query output |
| 9 | Assessed the detection status | Detection not yet validated; root cause unresolved |
| 10 | Defined follow-up checks | Inspect raw Sysmon records, verify field values, confirm test-event ingestion, and validate matching conditions independently |

## Evidence Interpretation

The baseline query confirms that records matching event code `1` are available in Elasticsearch and that the main group is associated with the expected Sysmon provider and dataset.

The controlled PowerShell commands were executed locally, but their corresponding indexed events were not confirmed in the supplied results. The zero-result detection query therefore cannot yet be attributed to a specific field, matching condition, or ingestion issue.

## Current Status

**Status: Detection validation in progress**

### Confirmed

- Sysmon process-creation records are represented in the queried Elasticsearch data.
- The baseline aggregation returned a primary group of 51,901 records.
- Controlled PowerShell test commands were executed.
- The initial detection query returned no matching results.

### Pending

- Verify the process fields in individual Sysmon documents.
- Locate the controlled test events in Elasticsearch.
- Determine which detection condition prevents matching.
- Validate positive and negative test cases.
- Evaluate false positives and decide whether the rule is ready for operational use.

No confirmed malicious activity was established during this lab.

# Investigation Notes 

## 1. Evidence Collected

### Evidence A — Baseline Query

Query:

```esql
FROM logs-*
| WHERE event.code == "1"
| STATS event_count = COUNT(*) BY
    host.name,
    event.provider,
    event.dataset,
    event.module
| SORT event_count DESC
| LIMIT 50
```

Observed output:

- Approximately 52,000 documents processed.
- Eight grouped results displayed.
- The primary group contained 51,901 records.
- Host: `desktop-9mmm37v`.
- Provider: `Microsoft-Windows-Sysmon`.
- Dataset: `windows.sysmon_operational`.
- Module: `windows`.

Interpretation:

The query returned a large group of records matching the event-code filter. The provider and dataset values are consistent with Sysmon Operational telemetry.

This confirms the presence of matching Sysmon records in the queried data. It does not prove that every required process field is populated or that the controlled PowerShell tests are represented in those records.

### Evidence B — Initial Detection Query

The detection query applied the following conditions:

- Event code equals `1`.
- Process name is present.
- Process command line is present.
- Process name matches `powershell.exe` or `pwsh.exe`.
- Command line contains an encoded-command or hidden-window indicator.

Observed output:

- Zero documents processed.
- No matching results displayed.

Interpretation:

The detection query did not produce any matches. The reason is unknown at this stage.

Potential explanations to investigate include:

- The process name or command-line fields are missing in the relevant records.
- The fields contain values that do not match the expected patterns.
- The process name is represented differently than expected.
- The controlled test events are outside the selected time range or are not indexed.
- One or more query conditions exclude otherwise relevant events.

These are investigation hypotheses, not confirmed root causes.

### Evidence C — Controlled PowerShell Tests

The following scenarios were executed:

| Test | Activity | Observed local behavior | Elastic detection status |
|---|---|---|---|
| A | Benign PowerShell command | Expected message displayed | Not confirmed |
| B | Encoded PowerShell command | Expected message displayed | Not confirmed |
| C | Hidden-window PowerShell command | Command returned without visible output | Not confirmed |

The encoded-command test used a Base64-encoded, harmless PowerShell instruction. The hidden-window test also used a harmless instruction.

Interpretation:

The local results show that the commands were invoked. They do not prove that their process-creation events were ingested or that the detection conditions matched those events.

The hidden-window command's lack of visible output is consistent with hidden-window execution, but it is not sufficient evidence of successful detection or malicious behavior.

## 2. Detection Logic Assessment

The initial detection combines several conditions. Each condition should be tested independently before the entire query is modified.

The most important validation questions are:

1. Do the Sysmon process-creation records contain `process.name`?
2. Do they contain `process.command_line`?
3. What exact values do these fields contain?
4. Do the controlled test events appear in the selected time range?
5. Does each `LIKE` pattern match the actual field representation?
6. Does the combined query return the expected test events?

A zero-result query should not immediately be interpreted as a failed Sysmon installation or a failed Elastic Agent. The baseline results show that relevant Sysmon records exist in Elasticsearch, but additional checks are required to establish the status of the specific test events.

## 3. Current Assessment

### Confirmed

- The baseline query returned records grouped under `Microsoft-Windows-Sysmon`.
- The primary group was associated with `windows.sysmon_operational`.
- The baseline reported 51,901 records in that group.
- Controlled PowerShell commands were executed locally.
- The initial detection query returned zero matching results.

### Not Yet Confirmed

- Whether the controlled test events were indexed.
- Whether the relevant process fields are populated in those events.
- Whether the initial detection patterns match the actual field values.
- Whether the query can detect the intended behavior after appropriate validation.
- Whether the detection produces acceptable false-positive results.

### Incident Classification

No confirmed security incident was established during this lab. The investigation concerns detection validation and telemetry visibility, not a confirmed compromise.


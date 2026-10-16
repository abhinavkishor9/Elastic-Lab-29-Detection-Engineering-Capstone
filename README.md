# Lab 29 — Detection Engineering Capstone

## Overview

This lab focuses on the detection engineering lifecycle using Elastic Security, ES|QL, and Windows Sysmon. The objective is to develop and validate detection logic for suspicious PowerShell execution, verify the required endpoint telemetry, and investigate why the initial detection query returns no results.

The investigation begins with a baseline query that identifies Windows Sysmon process-creation events in Elasticsearch. The baseline confirms that the expected provider and dataset are present, but the detection query does not return matching records despite controlled PowerShell commands being executed on the Windows endpoint.

The lab therefore focuses on both detection development and validation. A detection query must be supported by available telemetry, tested against controlled scenarios, and evaluated for false positives before it can be considered reliable.

## Lab Objectives

- Establish a baseline of Windows Sysmon process-creation telemetry in Elasticsearch.
- Identify the event provider, dataset, and module associated with process-creation records.
- Develop ES|QL detection logic for suspicious PowerShell command-line characteristics.
- Execute controlled PowerShell test cases to evaluate detection coverage.
- Investigate why the initial detection query returns no results.
- Validate field availability and query matching before changing detection logic.
- Document confirmed findings, unresolved issues, limitations, and recommended next steps.

## Environment

| Component | Details |
|---|---|
| SIEM and investigation platform | Elastic Security / Kibana |
| Query language | ES|QL |
| Data view | `logs-*` |
| Endpoint | `desktop-9mmm37v` |
| Operating system | Windows 11 |
| Endpoint telemetry | Windows Sysmon |
| Sysmon provider | `Microsoft-Windows-Sysmon` |
| Sysmon dataset | `windows.sysmon_operational` |
| Detection use case | Suspicious PowerShell execution |
| Testing approach | Controlled, benign PowerShell commands |

## Detection Scenario

PowerShell is commonly used for system administration, automation, and software deployment. It can also be abused by attackers to execute commands, conceal activity, or run encoded instructions.

This detection hypothesis focuses on PowerShell process-creation events containing command-line characteristics such as:

- Encoded-command options.
- Hidden-window options.
- Other contextual indicators that may warrant investigation.

These characteristics are not proof of malicious activity. Legitimate administrative workflows can use similar options, so the detection must be evaluated in context.

## Investigation Workflow

1. Establish a baseline of process-creation events.
2. Verify the source provider and dataset.
3. Develop the initial ES|QL detection query.
4. Execute controlled PowerShell test cases.
5. Compare expected behavior with the indexed telemetry.
6. Investigate the zero-result detection query.
7. Document limitations and the additional validation required.

## Baseline Telemetry Validation

The following query was used to inspect process-creation event metadata:

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

### Observed Results

The query processed approximately 52,000 documents and returned eight grouped results.

The primary result was:

| Field | Observed value |
|---|---|
| Host | `desktop-9mmm37v` |
| Event count | 51,901 |
| Event provider | `Microsoft-Windows-Sysmon` |
| Event dataset | `windows.sysmon_operational` |
| Event module | `windows` |

Additional groups included records from `system.system`, with providers associated with `Microsoft-Windows-IsolatedUserMode` and `Microsoft-Windows-Kernel-General`.

The baseline confirms that a substantial volume of records matches the event-code filter and that Sysmon process-creation telemetry is represented in the queried data.

## Initial Detection Query

The following query was used to identify PowerShell process-creation events with suspicious command-line characteristics:

```esql
FROM logs-*
| WHERE event.code == "1"
| WHERE process.name IS NOT NULL
| WHERE process.command_line IS NOT NULL
| WHERE process.name LIKE "*powershell.exe"
    OR process.name LIKE "*pwsh.exe"
| WHERE process.command_line LIKE "*-enc*"
    OR process.command_line LIKE "*-encodedcommand*"
    OR process.command_line LIKE "*-windowstyle hidden*"
    OR process.command_line LIKE "*-w hidden*"
| KEEP @timestamp, host.name, user.name,
       process.name, process.executable,
       process.command_line, process.pid,
       event.provider, event.dataset
| SORT @timestamp DESC
| LIMIT 100
```

### Detection Result

The initial detection query returned no matching results.

The query therefore remains unvalidated. The result does not establish whether the issue is caused by missing fields, unexpected field values, matching behavior, or another query or telemetry limitation.

## Controlled PowerShell Tests

Three controlled scenarios were executed on the Windows endpoint:

1. A benign PowerShell command that writes a message to the console.
2. An encoded PowerShell command containing a harmless `Write-Output` instruction.
3. A hidden-window PowerShell command containing a harmless `Write-Output` instruction.

The commands executed locally, and the encoded-command test displayed its expected output. However, the corresponding events were not demonstrated in the detection query results.

Local command execution does not independently prove that the expected event was indexed or matched by the query.

## Key Findings

- The baseline query returned 51,901 records grouped under the Sysmon provider and `windows.sysmon_operational` dataset.
- The initial detection query returned zero matching results.
- Controlled PowerShell commands were executed on the endpoint.
- The evidence does not yet establish that the detection logic correctly identifies the controlled test events.
- The underlying reason for the zero-result query remains unresolved.
- No malicious activity or security incident was confirmed by this lab.

## Limitations

- The original process field values have not yet been verified against the controlled test executions.
- The exact reason for the zero-result query has not been established.
- Positive and negative detection coverage remains unconfirmed.
- False-positive rates have not been measured.
- No successful scheduled-rule alert has been demonstrated.

## Conclusion

Lab 29 demonstrates the importance of validating detection logic against actual endpoint telemetry. The baseline query confirms that Sysmon process-creation records are present in Elasticsearch, but the intended PowerShell detection returns no results.

The next step is to inspect individual Sysmon process-creation documents, verify the actual process and command-line field values, and test each filtering condition independently. The detection should only be considered validated after the controlled tests produce the expected results and relevant false-positive scenarios have been evaluated.

The primary lesson is that a detection query must be supported by evidence, not merely by a plausible hypothesis.

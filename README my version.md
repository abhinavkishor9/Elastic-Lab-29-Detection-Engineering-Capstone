# Elastic-Lab-29-Detection-Engineering-Capstone
## Overview
A Detection Engineering Capstone is an end-to-end project in which you take a realistic security threat, translate its behavior into a detection hypothesis, create a detection rule, generate or identify relevant telemetry, test the rule, evaluate false positives, and document the results.
In a typical SOC investigation, an analyst receives an alert and investigates what happened. In detection engineering, you work one step earlier: you design and validate the logic that should generate the alert in the first place.
1. Define the threat
Describe the attacker behavior and what you need to detect.
|
v
2. Identify telemetry
Find the events and fields needed to recognize the behavior.
|
v
3. Build the detection
Write and document the query or rule logic.
|
v
4. Test and tune
Validate test cases, investigate misses, and reduce false positives.
|
v
5. Document the outcome
Record evidence, limitations, severity rationale, and next steps.

This lab focuses on the detection engineering lifecycle using Elastic Security, ES|QL, and Windows Sysmon. The objective is to develop and validate detection logic for suspicious PowerShell execution, verify the required endpoint telemetry, and investigate why the initial detection query returns no results.

The investigation begins with a baseline query that identifies Windows Sysmon process-creation events in Elasticsearch. The baseline confirms that the expected provider and dataset are present, but the detection query does not return matching records despite controlled PowerShell commands being executed on the Windows endpoint.

The lab therefore focuses on both detection development and validation. A detection query must be supported by available telemetry, tested against controlled scenarios, and evaluated for false positives before it can be considered reliable.

## Lab Objectives

- Define a detection hypothesis for suspicious PowerShell execution based on observable process-creation behavior.
- Establish a baseline of Windows Sysmon process-creation telemetry using ES|QL.
- Validate event providers, datasets, and relevant process fields before developing detection logic.
- Create ES|QL queries to identify PowerShell executions containing encoded-command and hidden-window options.
- Execute controlled PowerShell test cases to evaluate the expected detection behavior.
- Investigate zero-result queries by examining field availability, actual field values, time ranges, and individual query conditions.
- Test detection conditions independently before combining them into a complete detection query.
- Evaluate positive and negative test cases to identify detection gaps and potential false positives.
- Document detection logic, testing evidence, tuning decisions, and unresolved limitations.
- Assess the readiness of the validated detection for implementation as a scheduled Elastic Security rule.
- Produce an evidence-based detection report that distinguishes confirmed findings from hypotheses and does not treat suspicious indicators as proof of malicious activity.

# Lab Scenario 
You are working as a SOC analyst responsible for developing and validating detections in Elastic Security. During this lab, you are tasked with identifying potentially suspicious PowerShell execution using Windows Sysmon process-creation events and ES|QL.

PowerShell is widely used for legitimate administration and automation, but attackers can also abuse it to execute encoded commands or conceal execution through hidden-window options. Your objective is to develop detection logic that identifies these characteristics while avoiding the assumption that every matching command is malicious.

You begin by examining the available Sysmon telemetry in Elasticsearch. The baseline query returns a substantial number of process-creation records associated with the expected Sysmon provider and dataset. However, the initial detection query returns no matching results, even after controlled PowerShell commands are executed on the Windows endpoint.

### Investigation Tasks

- Validate the available process-creation telemetry and identify the fields required for the detection.
- Develop ES|QL logic to identify PowerShell executions containing encoded-command or hidden-window options.
- Execute controlled, harmless PowerShell test cases and determine whether their corresponding events are available in Elasticsearch.
- Investigate the zero-result query by checking field values, event metadata, time ranges, and individual filtering conditions.
- Evaluate the detection against positive and negative test cases before considering it suitable for operational use.

### Investigation Approach

Follow an evidence-driven workflow, beginning with telemetry validation and progressing to detection development, testing, and tuning. Inspect individual Sysmon records before assuming that the required process fields are populated or represented in the expected format.

If the detection query fails to return results, test each filtering condition independently and determine whether the issue relates to the query logic, field availability, or missing test-event evidence. Avoid changing configurations or rebuilding components without evidence that such actions are necessary.

### Expected Outcome

Produce a documented detection engineering assessment containing the detection hypothesis, ES|QL query, test results, troubleshooting evidence, and recommendations for improvement.

The final assessment should distinguish confirmed observations from unresolved possibilities. The detection must not be considered successful until the expected test events are matched and its limitations are documented. The goal is to demonstrate a repeatable detection engineering process that produces reliable, evidence-supported results rather than simply creating a query that appears technically plausible.


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


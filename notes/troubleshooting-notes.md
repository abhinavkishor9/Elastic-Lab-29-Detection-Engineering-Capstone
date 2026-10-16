# Troubleshooting Notes — Lab 29: Detection Engineering Capstone

## Issue

The initial ES|QL detection query for suspicious PowerShell execution returned zero results, even though the baseline query returned a large number of Sysmon process-creation records and controlled PowerShell commands were executed locally.

## 1. Confirm the Baseline

Run the baseline query:

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

Observed result:

- Approximately 52,000 documents processed.
- 51,901 records in the primary Sysmon group.
- Host: `desktop-9mmm37v`.
- Dataset: `windows.sysmon_operational`.

This establishes that records matching the event-code filter are available. It does not establish that the process fields required by the detection are populated.

## 2. Inspect Raw Process-Creation Records

Start with a query that does not filter on process name or command line:

```esql
FROM logs-*
| WHERE event.code == "1"
| KEEP @timestamp, host.name,
       event.provider, event.dataset, event.module,
       process.name, process.executable,
       process.command_line, process.pid, user.name
| SORT @timestamp DESC
| LIMIT 30
```

Review the returned documents.

Check whether:

- `event.provider` is `Microsoft-Windows-Sysmon`.
- `event.dataset` is `windows.sysmon_operational`.
- `process.name` contains an executable name.
- `process.command_line` contains the original command-line arguments.
- The timestamps cover the period when the test commands were executed.

If the process fields are empty, investigate the source documents and field mappings before changing the detection patterns.

## 3. Check Whether Process Fields Are Populated

Use an aggregation to measure field availability:

```esql
FROM logs-*
| WHERE event.code == "1"
| WHERE event.provider == "Microsoft-Windows-Sysmon"
| STATS total = COUNT(*),
        with_process_name = COUNT(process.name),
        with_command_line = COUNT(process.command_line),
        with_executable = COUNT(process.executable)
  BY host.name, event.dataset
| SORT total DESC
```

Compare the total record count with the counts for each process field.

This helps determine whether the fields are generally populated in the relevant dataset. It does not by itself prove that the controlled test events have those fields.

## 4. Test the Process-Name Filter

If the fields are available, test the process-name condition separately:

```esql
FROM logs-*
| WHERE event.code == "1"
| WHERE event.provider == "Microsoft-Windows-Sysmon"
| WHERE process.name IS NOT NULL
| KEEP @timestamp, process.name,
       process.executable, process.command_line
| SORT @timestamp DESC
| LIMIT 100
```

Inspect the actual process-name values. Confirm whether the field contains a basename, a path, or another representation.

Then test the expected executable names:

```esql
FROM logs-*
| WHERE event.code == "1"
| WHERE event.provider == "Microsoft-Windows-Sysmon"
| WHERE process.name LIKE "*powershell.exe"
    OR process.name LIKE "*pwsh.exe"
| KEEP @timestamp, process.name,
       process.executable, process.command_line
| SORT @timestamp DESC
| LIMIT 100
```

If the query returns no results, compare the actual values from the previous query with the expected patterns. Do not assume the field representation.

## 5. Test Command-Line Patterns Independently

Once the process-name filter is verified, inspect command-line values before adding all the suspicious-option conditions:

```esql
FROM logs-*
| WHERE event.code == "1"
| WHERE event.provider == "Microsoft-Windows-Sysmon"
| WHERE process.command_line IS NOT NULL
| WHERE process.name LIKE "*powershell.exe"
    OR process.name LIKE "*pwsh.exe"
| KEEP @timestamp, process.name,
       process.command_line, process.pid, user.name
| SORT @timestamp DESC
| LIMIT 100
```

Review the exact command-line values. Check whether the controlled commands are present and whether the options are represented as expected.

If the field contains the controlled command lines, test one pattern at a time. For example:

```esql
FROM logs-*
| WHERE event.code == "1"
| WHERE event.provider == "Microsoft-Windows-Sysmon"
| WHERE process.command_line IS NOT NULL
| WHERE process.command_line LIKE "*-encodedcommand*"
| KEEP @timestamp, process.name,
       process.command_line, process.pid
| SORT @timestamp DESC
| LIMIT 100
```

If the pattern returns no results, inspect the raw values and verify the matching behavior before changing the detection logic.

## 6. Check the Test Time Range

The controlled PowerShell commands were executed locally, but the screenshots do not establish the exact indexed timestamps of their corresponding process-creation events.

Use a Kibana time range that includes the test period. If necessary, rerun one controlled test, note the local time, wait for ingestion, and search the corresponding time window.

Do not assume that a command appearing in the local console proves its event was indexed.

## 7. Rebuild the Detection Incrementally

After confirming the relevant event fields and matching behavior, add the detection conditions in stages:

1. Filter to the verified Sysmon provider and process-creation event.
2. Confirm process-name matching.
3. Confirm command-line availability.
4. Add one suspicious command-line pattern.
5. Test the remaining patterns separately.
6. Combine the validated conditions.
7. Repeat the controlled tests and document the results.

This approach makes it easier to identify which condition excludes the expected records.

## 8. Troubleshooting Decision Table

| Observation | Next action |
|---|---|
| Baseline returns Sysmon records, but process fields are empty | Inspect source documents, field availability, and ingestion details |
| Process name exists, but the executable filter returns no results | Inspect exact values and validate `LIKE` matching |
| Process records exist, but test commands are absent | Check the time range and event ingestion for the controlled tests |
| Individual patterns work, but the combined query does not | Add conditions incrementally and validate the combined logic |
| Detection query returns expected test events | Continue with false-positive evaluation and rule validation |
| Query returns zero results after all checks | Record the remaining evidence and investigate the unresolved cause |

## Conclusion

The current evidence does not identify a definitive root cause. The baseline confirms that Sysmon process-creation records are available in Elasticsearch, but the detection query has not demonstrated successful matching.

Prioritize read-only field inspection and incremental query testing. Do not reinstall Sysmon, re-enroll Elastic Agent, or change ingestion configuration without evidence that those actions address the actual problem.

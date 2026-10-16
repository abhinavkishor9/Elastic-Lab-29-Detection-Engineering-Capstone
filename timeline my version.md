# Investigation Timeline
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


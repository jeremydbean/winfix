# Documenting backup protection with WinFix

Use this guide with collector 1.12 or later. The collector supplies local evidence;
the backup console and a documented restore test supply the remaining proof.
Record the machine name, audit collection time and timezone alongside every job.
Keep customer evidence outside the public source repository.

## Collect a more complete sample

Run in an elevated 64-bit PowerShell ISE script pane, then paste the opened report
text back for analysis. This downloads the collector, runs the whole-machine deep
audit and increases the bounded Veeam sample. TLS settings are restored afterward.

```powershell
& {
    $previousTls = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $auditUrl = 'https://raw.githubusercontent.com/jeremydbean/winfix/main/Export-WinFixAudit.ps1'
        $auditScript = Invoke-RestMethod -Uri $auditUrl -TimeoutSec 60 -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace([string]$auditScript)) { throw 'Empty download.' }
        & ([scriptblock]::Create([string]$auditScript)) -CopyToClipboard -DeepAudit `
            -MaxVeeamLogFiles 20 -VeeamDiscoveryEntryLimit 8000 -VeeamLogTailKiB 512
    }
    finally {
        [Net.ServicePointManager]::SecurityProtocol = $previousTls
    }
}
```

Check `VeeamLogDiscovery` for `ScanLimitReached`, `DirectoriesCapped`,
`DeeperFoldersSkipped`, access errors and `OutputTruncated`. Review the collection
status as well as the contents: `Unavailable`, `TimedOut` or `Partial` are coverage
gaps. `Collected` means the check returned, not that the backups are healthy.

If a particular job was omitted, perform a separate capture with
`-VeeamLogDirectory 'C:\ProgramData\Veeam\Backup\ExampleJob'` added to the collector
invocation. Use an existing local job directory confirmed on that machine. Keep
both captures: the job-specific run will not include the root service log.
Increasing a limit cannot recover a deleted log, a completion outside the retained
tail, an archived file, or an inaccessible folder.

## Interpret the evidence accurately

| Observation | What it supports | What remains to verify |
| --- | --- | --- |
| Recent `Task.*` file modification | The file changed recently | Which session/workload it describes; backup completion |
| No keyword excerpts, but `RecentActivity` exists | The retained tail has activity text | Whether progress continues; completion may be outside the tail |
| `Result: [Success]` in a configuration snapshot | A stored status value was logged | Actual last completed session and restore-point date |
| `Success` for `InfraStatistic` or `VolumesDiscover` | A recognized infrastructure operation succeeded | Whether a backup session succeeded |
| Repository/network-path error with nearby context | A repository operation encountered a connection problem | Exact destination, gateway, affected job and whether a later retry recovered |
| Backup session completed successfully | A specific session reported success | Each workload's restore point, application consistency and recoverability |
| VSS writer waiting, with no writer error | Writer state at collection time | Correlation with an active session and later return to stable state |
| Old VSS error | An earlier snapshot operation failed | Whether it affected the current job or was followed by a successful retry |

Use timestamps and session identifiers to connect related lines. Do not associate
a standalone schedule/last-run line with the nearest named job unless the log
structure or console confirms it. Evidence labels are text heuristics; review the
underlying excerpt. Timestamp strings do not establish timezone. Missing evidence
must remain unknown, rather than being marked failed or passed automatically.

## Follow up repository errors

1. Identify the job, repository, gateway and exact configured destination from the
   console and the error context. Record the time and session ID.
2. From the relevant gateway or backup server, verify destination availability,
   name resolution, the required connection, free space and backup-service access.
   An administrator's interactive mapped drive does not demonstrate that the
   service identity can access the same location.
3. Inspect the latest session and retry outcome. Record whether the error is still
   active, recovered, or historical; include the evidence time.
4. Confirm each expected workload has a recent usable restore point. Test a restore
   using the organization's approved procedure and document the result.

The collector does not change jobs, access NAS credentials, validate repository
contents, or perform a restore. A backup copy job and the primary backup job should
have separate evidence records so a healthy source does not conceal a failed copy.
Veeam documents the source/target relationship in
[Linking Backup Jobs to Backup Copy Jobs](https://helpcenter.veeam.com/docs/vbr/userguide/linking_backup_to_copy.html).
For full vendor support logs beyond this bounded collector sample, use
[Veeam KB1832](https://www.veeam.com/kb1832).

## Per-job documentation worksheet

Copy one block for each backup or copy job; use Unknown when evidence is missing.
Do not put passwords, tokens, or recovery keys in this record.

```text
Machine / role:
Audit collected at / timezone:
Backup product / version:
Job name / type (backup, replication, copy, file backup, sync):
Workloads or volumes included / exclusions:
Job-to-workload identity verified from:
Schedule / timezone / expected recovery point objective:
Latest completed session time / timezone / session ID / result:
Latest restore point for EACH workload:
Application-consistent / crash-consistent / unknown:
Repository / gateway / configured destination:
Destination availability / free capacity evidence and time:
Retention / oldest and newest available restore points:
Encryption in transit / at rest (evidence source):
Offsite copy / immutability / isolation (evidence source):
Most recent restore test date / workload / result / duration:
Current failures or warnings / affected session:
Historical errors / evidence of subsequent recovery:
Collector omissions / manual checks still needed:
Owner / priority / next action / target date:
Evidence source (audit section, console capture or restore-test record):
```

For a ticket note, lead with the latest verified restore point and current impact,
then list unresolved errors and the next action. Distinguish confirmed failures,
historical errors and unknown protection. Successful file synchronization alone
does not document system recovery, retained historical versions or a tested restore.

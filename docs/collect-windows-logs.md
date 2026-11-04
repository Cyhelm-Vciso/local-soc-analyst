# Collecting Windows logs

`soc-analyst` reads Windows events as JSON or JSONL in either of two shapes.

## Option 1: PowerShell export (no extra tools)

Run in an elevated PowerShell. It flattens each event's `EventData` into one JSON line:

```powershell
$since = (Get-Date).AddDays(-1)
$filters = @(
  @{LogName='Security'; Id=4624,4625,4688,4698,4720,4728,4732,4756,1102; StartTime=$since},
  @{LogName='System'; Id=7045,104; StartTime=$since},
  @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$since}
)
$filters | ForEach-Object { Get-WinEvent -FilterHashtable $_ -ErrorAction SilentlyContinue } | ForEach-Object {
  $x = [xml]$_.ToXml()
  $o = [ordered]@{
    EventID     = $_.Id
    TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
    Computer    = $_.MachineName
    Channel     = $_.LogName
  }
  foreach ($d in $x.Event.EventData.Data) { if ($d.Name) { $o[$d.Name] = $d.'#text' } }
  [pscustomobject]$o | ConvertTo-Json -Compress
} | Set-Content -Encoding utf8 events.jsonl
```

Then run:

```bash
soc-analyst analyze events.jsonl -o report.md
```

Notes:
- Process creation events (4688) only include `CommandLine` if *"Include command line in process creation events"* is enabled by Group Policy.
- Sysmon gives far richer process telemetry (parent process, full command line). Install it with a well-known community configuration.

## Option 2: `evtx_dump` (offline .evtx files)

For `.evtx` files collected during an investigation, use [evtx_dump](https://github.com/omerbenamram/evtx):

```bash
evtx_dump -o jsonl Security.evtx > security.jsonl
```

```bash
soc-analyst analyze security.jsonl
```

The nested `{"Event": {"System": …, "EventData": …}}` structure is detected automatically.

## Linux

Point the tool at `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Fedora):

```bash
sudo soc-analyst analyze /var/log/auth.log --format authlog --year 2026
```

Classic syslog lines have no year; `--year` sets it (default: the current year).

On systemd-only systems, export the journal first:

```bash
journalctl -u ssh -u sshd --since "24 hours ago" -o short-iso > auth.log
```

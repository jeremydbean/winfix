[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Message,

    [Parameter(Mandatory = $false)]
    [string[]]$Notes = @(),

    [Parameter(Mandatory = $false)]
    [switch]$NoChangelog,

    [Parameter(Mandatory = $false)]
    [string]$ChangelogPath = (Join-Path $PSScriptRoot '..' 'CHANGELOG.md')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Git {
    param([Parameter(Mandatory)] [string[]]$Args)
    $git = Get-Command git -ErrorAction Stop
    & $git @Args
}

function Add-ChangelogEntry {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string[]]$Bullets
    )

    $date = (Get-Date).ToString('yyyy-MM-dd')
    $entry = @()
    $entry += "## $date"
    foreach ($b in $Bullets) {
        if (-not [string]::IsNullOrWhiteSpace($b)) {
            $entry += "- $b"
        }
    }
    $entry += ''

    if (-not (Test-Path $Path)) {
        $content = @("# Changelog", '', @($entry)) -join "`n"
        $content | Out-File -FilePath $Path -Encoding UTF8
        return
    }

    $existing = Get-Content -Path $Path -Raw -ErrorAction Stop

    if ($existing -match "(?m)^#\s+Changelog\s*$") {
        $lines = $existing -split "`n"
        $out = New-Object System.Collections.Generic.List[string]

        $out.Add('# Changelog') | Out-Null
        $out.Add('') | Out-Null

        # Remove leading header if present
        $startAt = 0
        for ($i = 0; $i -lt $lines.Length; $i++) {
            if ($lines[$i] -match '^#\s+Changelog\s*$') {
                $startAt = $i + 1
                break
            }
        }

        # Skip any blank lines after header
        while ($startAt -lt $lines.Length -and [string]::IsNullOrWhiteSpace($lines[$startAt])) {
            $startAt++
        }

        foreach ($e in $entry) { $out.Add($e) | Out-Null }
        for ($i = $startAt; $i -lt $lines.Length; $i++) { $out.Add($lines[$i]) | Out-Null }

        ($out -join "`n").TrimEnd() + "`n" | Out-File -FilePath $Path -Encoding UTF8
        return
    }

    # Fallback: prepend entry
    ("# Changelog`n`n" + ($entry -join "`n") + $existing) | Out-File -FilePath $Path -Encoding UTF8
}

if (-not $NoChangelog) {
    $bullets = if ($Notes -and $Notes.Count -gt 0) { $Notes } else { @($Message) }
    Add-ChangelogEntry -Path $ChangelogPath -Bullets $bullets
}

Invoke-Git -Args @('add', '-A')
Invoke-Git -Args @('status', '--porcelain=v1')

Invoke-Git -Args @('commit', '-m', $Message)

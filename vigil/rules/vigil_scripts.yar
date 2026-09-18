/*
 * VIGIL built-in YARA rules for script triage.
 *
 * These run over EVERY deobfuscation layer, so a payload three decodes deep
 * is matched like plaintext. Rules are behavior-focused; meta carries the
 * category, ATT&CK id, and severity that the scorer and reporter consume.
 *
 * These rules are matched against input as DATA. Nothing here is executed.
 */

rule powershell_download_cradle
{
    meta:
        category = "download"
        attack_id = "T1105"
        severity = "high"
        description = "PowerShell one-liner that fetches and runs remote code"
    strings:
        $webclient = "New-Object Net.WebClient" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $iex = "IEX" nocase
        $iex2 = "Invoke-Expression" nocase
    condition:
        ($webclient or $dl1 or $dl2) and ($iex or $iex2)
}

rule powershell_encoded_command
{
    meta:
        category = "execution"
        attack_id = "T1027"
        severity = "high"
        description = "PowerShell -EncodedCommand base64 payload"
    strings:
        $enc = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{20,}/ nocase
    condition:
        $enc
}

rule reverse_shell_unix
{
    meta:
        category = "c2"
        attack_id = "T1095"
        severity = "high"
        description = "Unix reverse/bind shell one-liners"
    strings:
        $devtcp = "/dev/tcp/"
        $bashi = /bash\s+-i\s*>&/
        $nce = /nc(at)?\b[^\n]{0,40}-e\b/
        $mkfifo = /mkfifo[^\n]{0,60}\|\s*(ba)?sh/
    condition:
        any of them
}

rule credential_access_unix
{
    meta:
        category = "credential_access"
        attack_id = "T1003.008"
        severity = "high"
        description = "Reads Unix credential stores"
    strings:
        $shadow = "/etc/shadow"
        $passwd = "/etc/passwd"
    condition:
        $shadow or ($passwd and filesize < 1MB)
}

rule mimikatz_reference
{
    meta:
        category = "credential_access"
        attack_id = "T1003.001"
        severity = "high"
        description = "References to Mimikatz / LSASS credential dumping"
    strings:
        $m1 = "mimikatz" nocase
        $m2 = "sekurlsa" nocase
        $m3 = "Invoke-Mimikatz" nocase
        $lsass = "lsass" nocase
        $dump = "MiniDump" nocase
    condition:
        $m1 or $m2 or $m3 or ($lsass and $dump)
}

rule defender_tampering
{
    meta:
        category = "anti_forensics"
        attack_id = "T1562.001"
        severity = "high"
        description = "Disables Windows Defender / AV"
    strings:
        $d1 = "Set-MpPreference" nocase
        $d2 = "DisableRealtimeMonitoring" nocase
        $d3 = "DisableAntiSpyware" nocase
        $d4 = "Add-MpPreference" nocase
    condition:
        ($d1 or $d4) and ($d2 or $d3) or $d2
}

rule clear_event_logs
{
    meta:
        category = "anti_forensics"
        attack_id = "T1070.001"
        severity = "high"
        description = "Clears Windows event logs"
    strings:
        $c1 = "Clear-EventLog" nocase
        $c2 = "wevtutil cl" nocase
        $c3 = "wevtutil clear-log" nocase
    condition:
        any of them
}

rule scheduled_task_persistence
{
    meta:
        category = "persistence"
        attack_id = "T1053.005"
        severity = "medium"
        description = "Creates a scheduled task for persistence"
    strings:
        $s1 = "schtasks" nocase
        $create = "/create" nocase
        $reg = "Register-ScheduledTask" nocase
    condition:
        ($s1 and $create) or $reg
}

rule registry_run_key_persistence
{
    meta:
        category = "persistence"
        attack_id = "T1547.001"
        severity = "high"
        description = "Writes an autorun registry key"
    strings:
        $run = /(HKLM|HKCU|HKEY_[A-Z_]+)\\[^\n]{0,80}\\Run(Once)?/ nocase
        $regadd = "reg add" nocase
    condition:
        $run or ($regadd and $run)
}

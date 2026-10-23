rule Trojan_Win32_SusPrivChecks_B_2147955609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPrivChecks.B"
        threat_id = "2147955609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPrivChecks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Unblock-File" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "Get-WinUpdates" ascii //weight: 1
        $x_1_5 = "Import-Module" ascii //weight: 1
        $x_1_6 = "-ComputerName localhost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

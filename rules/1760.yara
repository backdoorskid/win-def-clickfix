rule Trojan_Win32_SusPrivCheck_B_2147954156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPrivCheck.B"
        threat_id = "2147954156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPrivCheck"
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
        $n_1_7 = "69802c98-2cp2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

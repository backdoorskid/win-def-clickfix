rule Trojan_Win32_SusPrivCheck_A_2147954155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPrivCheck.A"
        threat_id = "2147954155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPrivCheck"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Unblock-File" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_4 = "Invoke-PrivescCheck" ascii //weight: 1
        $x_1_5 = "Import-Module" ascii //weight: 1
        $n_1_6 = "69802c98-2co2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

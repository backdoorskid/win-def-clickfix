rule Trojan_Win32_SusPrivChecks_A_2147955608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPrivChecks.A"
        threat_id = "2147955608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPrivChecks"
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
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusRegistryModification_A_2147954188_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegistryModification.A"
        threat_id = "2147954188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Unblock-File" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp\\T1112.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

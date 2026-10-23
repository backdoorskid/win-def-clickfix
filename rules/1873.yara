rule Trojan_Win32_SusRegistryModification_C_2147954190_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegistryModification.C"
        threat_id = "2147954190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "mi_wdigest.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

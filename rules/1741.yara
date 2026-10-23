rule Trojan_Win32_SuspRegistryModification_C_2147954179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.C"
        threat_id = "2147954179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "mi_wdigest.ps1" ascii //weight: 1
        $n_1_4 = "4b79ffab-a220-4ed5-a63d-1f1a9045113k" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspRegistryModification_J_2147954186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.J"
        threat_id = "2147954186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" ascii //weight: 1
        $x_1_3 = "/v HideFileExt" ascii //weight: 1
        $x_1_4 = "rundll32.exe" ascii //weight: 1
        $x_1_5 = "/t REG_DWORD" ascii //weight: 1
        $x_1_6 = " /d" wide //weight: 1
        $x_1_7 = " /f" wide //weight: 1
        $n_1_8 = "4b79ffab-a220-4ed5-a63d-1f1a9045113r" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

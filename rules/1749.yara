rule Trojan_Win32_SuspRegistryModification_K_2147954187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRegistryModification.K"
        threat_id = "2147954187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "/v SecurityHealth" ascii //weight: 1
        $x_1_4 = "rundll32.exe" ascii //weight: 1
        $x_1_5 = "/t REG_EXPAND_SZ" ascii //weight: 1
        $x_1_6 = "/d test.exe /f" ascii //weight: 1
        $n_1_7 = "4b79ffab-a220-4ed5-a63d-1f1a9045113s" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

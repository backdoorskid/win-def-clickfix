rule Trojan_Win32_SusRegistryModification_J_2147955632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegistryModification.J"
        threat_id = "2147955632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegistryModification"
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
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

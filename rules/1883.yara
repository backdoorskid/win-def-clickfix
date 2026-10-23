rule Trojan_Win32_SusRegistryModification_I_2147955631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusRegistryModification.I"
        threat_id = "2147955631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusRegistryModification"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg.exe add" ascii //weight: 1
        $x_1_2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "/v " wide //weight: 1
        $x_1_4 = "rundll32.exe" ascii //weight: 1
        $x_1_5 = "/t REG_SZ /d" ascii //weight: 1
        $x_1_6 = " /f" wide //weight: 1
        $x_1_7 = "ProgramData\\RasCon\\RasCon.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

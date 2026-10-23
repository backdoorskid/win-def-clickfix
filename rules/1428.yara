rule Trojan_Win32_SusDarkCrystal_A_2147955539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDarkCrystal.A"
        threat_id = "2147955539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDarkCrystal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe " ascii //weight: 1
        $x_1_2 = "Get-Random " ascii //weight: 1
        $x_1_3 = "-Minimum " ascii //weight: 1
        $x_1_4 = "-Maximum" ascii //weight: 1
        $x_1_5 = "Start-Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

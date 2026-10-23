rule Trojan_Win32_SusDarkCrystal_B_2147955542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusDarkCrystal.B"
        threat_id = "2147955542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusDarkCrystal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe " ascii //weight: 1
        $x_1_2 = "New-Item -Path" ascii //weight: 1
        $x_1_3 = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Wininit" ascii //weight: 1
        $x_1_4 = " -Value " ascii //weight: 1
        $x_1_5 = "Sysdll32.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

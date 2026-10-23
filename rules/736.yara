rule Trojan_Win32_DarkCrystal_A_2147954074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkCrystal.A"
        threat_id = "2147954074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkCrystal"
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
        $n_1_6 = "9453e881-26a8-4973-ba2e-76269e901d0k" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

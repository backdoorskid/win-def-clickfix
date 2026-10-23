rule Trojan_Win32_SuspSetting_F_2147955605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSetting.F"
        threat_id = "2147955605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSetting"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WinSystemLocale" ascii //weight: 1
        $x_1_3 = "Select-Object" ascii //weight: 1
        $x_1_4 = "OEMCP" ascii //weight: 1
        $x_1_5 = "TextInfo.OemCodePage" ascii //weight: 1
        $x_1_6 = "TextInfo.AnsiCodePage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

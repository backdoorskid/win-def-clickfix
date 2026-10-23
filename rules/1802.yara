rule Trojan_Win32_SuspSettings_F_2147954152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSettings.F"
        threat_id = "2147954152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSettings"
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
        $n_1_7 = "69802c98-2cm2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

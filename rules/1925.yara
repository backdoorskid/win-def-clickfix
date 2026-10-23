rule Trojan_Win32_SusWmiPs_D_2147954149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWmiPs.D"
        threat_id = "2147954149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject" ascii //weight: 1
        $x_1_3 = "Win32_Processor" ascii //weight: 1
        $x_1_4 = "win32_desktopmonitor" ascii //weight: 1
        $x_1_5 = "win32_videocontroller" ascii //weight: 1
        $x_1_6 = "gdr" wide //weight: 1
        $x_1_7 = "-PSProvider" ascii //weight: 1
        $n_1_8 = "69802c98-2ck2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

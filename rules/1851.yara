rule Trojan_Win32_SuspWmiPs_D_2147955602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmiPs.D"
        threat_id = "2147955602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmiPs"
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
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

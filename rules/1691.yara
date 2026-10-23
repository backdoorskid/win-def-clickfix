rule Trojan_Win32_SuspProxi_E_2147955582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.E"
        threat_id = "2147955582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "ormat %SYSTEMDRIVE%" ascii //weight: 1
        $x_1_4 = "/fs:NPRunner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

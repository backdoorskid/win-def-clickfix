rule Trojan_Win32_SuspProxi_G_2147955584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.G"
        threat_id = "2147955584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msiexec.exe /q /i" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "in.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

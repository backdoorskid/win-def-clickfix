rule Trojan_Win32_SuspProxi_B_2147955579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.B"
        threat_id = "2147955579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta.exe" ascii //weight: 1
        $x_1_2 = "public" ascii //weight: 1
        $x_1_3 = "textboxNameNamespace.hta" ascii //weight: 1
        $x_1_4 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_5 = "start.hta" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

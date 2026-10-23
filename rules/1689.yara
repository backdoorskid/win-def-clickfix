rule Trojan_Win32_SuspProxi_C_2147955580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.C"
        threat_id = "2147955580"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c mkdir" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp\\lb\\Windows Media Player" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

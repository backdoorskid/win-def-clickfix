rule Trojan_Win32_SuspProxy_F_2147954131_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.F"
        threat_id = "2147954131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "timeout" ascii //weight: 1
        $x_1_3 = "tasklist /svc" ascii //weight: 1
        $x_1_4 = "findstr /i" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

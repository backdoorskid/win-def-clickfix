rule Trojan_Win32_SuspProxy_B_2147954127_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.B"
        threat_id = "2147954127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "advpack.dll" ascii //weight: 1
        $x_1_3 = "foobar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

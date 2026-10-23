rule Trojan_Win32_SuspProxy_A_2147954126_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.A"
        threat_id = "2147954126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "url.dll" ascii //weight: 1
        $x_1_3 = "FileProtocolHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

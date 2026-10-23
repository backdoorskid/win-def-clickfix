rule Trojan_Win32_SuspProxy_MK_2147955550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.MK"
        threat_id = "2147955550"
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
        $x_1_3 = "TelnetProtocolHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

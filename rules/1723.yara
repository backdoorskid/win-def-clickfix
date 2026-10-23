rule Trojan_Win32_SuspProxy_O_2147955572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.O"
        threat_id = "2147955572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c setx" ascii //weight: 1
        $x_1_2 = "PUBURL" ascii //weight: 1
        $x_1_3 = "http://pcsdl.com/short-url" ascii //weight: 1
        $x_1_4 = "dummy_empire_agent" ascii //weight: 1
        $x_1_5 = ".ps1 /m" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

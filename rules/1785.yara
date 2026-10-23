rule Trojan_Win32_SusProxy_O_2147954120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.O"
        threat_id = "2147954120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
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
        $n_1_6 = "69802c98-2ce2-4a17-98d0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

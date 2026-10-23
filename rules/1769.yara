rule Trojan_Win32_SusProxy_MK_2147954085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.MK"
        threat_id = "2147954085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "url.dll" ascii //weight: 1
        $x_1_3 = "TelnetProtocolHandler" ascii //weight: 1
        $n_1_4 = "69802c98-2ce2-4a17-98j0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

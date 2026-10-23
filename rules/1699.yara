rule Trojan_Win32_SuspProxy_B_2147954127_0
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
        $x_1_1 = "mshta.exe" ascii //weight: 1
        $x_1_2 = "public" ascii //weight: 1
        $x_1_3 = "textboxNameNamespace.hta" ascii //weight: 1
        $x_1_4 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_5 = "start.hta" ascii //weight: 1
        $n_1_6 = "69802c98-2ce2-4a17-98l0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

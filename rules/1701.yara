rule Trojan_Win32_SuspProxy_C_2147954128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.C"
        threat_id = "2147954128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c mkdir" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp\\lb\\Windows Media Player" ascii //weight: 1
        $n_1_3 = "69802c98-2ce2-4a17-98m0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

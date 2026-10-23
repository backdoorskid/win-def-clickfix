rule Trojan_Win32_DllExecuteAbuse_E_2147969774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllExecuteAbuse.E"
        threat_id = "2147969774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllExecuteAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "rundll32.exe" wide //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

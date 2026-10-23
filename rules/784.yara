rule Trojan_Win32_DllExecuteAbuse_B_2147957002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllExecuteAbuse.B"
        threat_id = "2147957002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllExecuteAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32_dll.dll" wide //weight: 1
        $x_1_2 = "writetotempfile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

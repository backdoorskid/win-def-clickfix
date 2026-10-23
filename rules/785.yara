rule Trojan_Win32_DllExecuteAbuse_C_2147961804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllExecuteAbuse.C"
        threat_id = "2147961804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllExecuteAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" wide //weight: 1
        $x_1_2 = "rundll32_dll" wide //weight: 1
        $x_1_3 = "writetotempfile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

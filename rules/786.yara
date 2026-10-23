rule Trojan_Win32_DllExecuteAbuse_D_2147969773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DllExecuteAbuse.D"
        threat_id = "2147969773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DllExecuteAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "rundll32.exe" wide //weight: 8
        $x_4_2 = "writetotempfile" wide //weight: 4
        $x_2_3 = "writetofile" wide //weight: 2
        $x_2_4 = "\\aiq-" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 2 of ($x_2_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

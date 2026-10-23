rule Trojan_Win32_Priteshel_B_2147783752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Priteshel.B"
        threat_id = "2147783752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Priteshel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_2_2 = "-enc" wide //weight: 2
        $x_1_3 = "bypass" wide //weight: 1
        $x_1_4 = "hidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_MPTamperSuspExlc_A_2147812067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MPTamperSuspExlc.A"
        threat_id = "2147812067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MPTamperSuspExlc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "powershell" wide //weight: 5
        $x_1_2 = "set-mppreference" wide //weight: 1
        $x_1_3 = "add-mppreference" wide //weight: 1
        $x_5_4 = "-exclusionpath" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

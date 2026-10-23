rule Trojan_PowerShell_Sacepos_B_2147726149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Sacepos.B"
        threat_id = "2147726149"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Sacepos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dl.dropboxusercontent" wide //weight: 1
        $x_1_2 = "dropbox.com/" wide //weight: 1
        $x_10_3 = ".ps1?dl=" wide //weight: 10
        $x_10_4 = {69 00 65 00 78 00 20 00 [0-3] 28 00 6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 6e 00 65 00 74 00 2e 00 77 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 27}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

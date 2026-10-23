rule Trojan_PowerShell_Sacepos_D_2147726585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Sacepos.D"
        threat_id = "2147726585"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Sacepos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 00 65 00 78 00 [0-2] 28 00 5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 74 00 65 00 78 00 74 00 2e 00 65 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 75 00 6e 00 69 00 63 00 6f 00 64 00 65 00 2e 00 67 00 65 00 74 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 66 00 72 00 6f 00 6d 00 62 00 61 00 73 00 65 00 36 00 34 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 28 00 67 00 65 00 74 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

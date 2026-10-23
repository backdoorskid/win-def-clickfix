rule Trojan_PowerShell_Timestomp_B_2147935847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Timestomp.B"
        threat_id = "2147935847"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Timestomp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 [0-6] 28 00 67 00 65 00 74 00 2d 00 63 00 68 00 69 00 6c 00 64 00 69 00 74 00 65 00 6d 00}  //weight: 10, accuracy: Low
        $x_10_2 = {29 00 2e 00 63 00 72 00 65 00 61 00 74 00 69 00 6f 00 6e 00 74 00 69 00 6d 00 65 00 [0-6] 3d 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

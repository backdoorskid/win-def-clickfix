rule Trojan_PowerShell_PsAttack_A_2147725500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/PsAttack.A"
        threat_id = "2147725500"
        type = "Trojan"
        platform = "PowerShell: "
        family = "PsAttack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 00 6d 00 73 00 69 00 75 00 74 00 69 00 6c 00 73 00 [0-16] 67 00 65 00 74 00 66 00 69 00 65 00 6c 00 64 00 28 00 [0-16] 61 00 6d 00 73 00 69 00 69 00 6e 00 69 00 74 00 66 00 61 00 69 00 6c 00 65 00 64 00}  //weight: 1, accuracy: Low
        $x_1_2 = {61 00 6d 00 73 00 69 00 63 00 6f 00 6e 00 74 00 65 00 78 00 74 00 [0-16] 5b 00 72 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 62 00 69 00 6e 00 64 00 69 00 6e 00 67 00 66 00 6c 00 61 00 67 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5b 00 72 00 65 00 66 00 5d 00 2e 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 2e 00 67 00 65 00 74 00 74 00 79 00 70 00 65 00 28 00 [0-2] 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 6d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 2e 00 61 00 75 00 74 00 6f 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 61 00 6d 00 73 00 69 00 75 00 74 00 69 00 6c 00 73 00}  //weight: 1, accuracy: Low
        $x_1_4 = {61 00 6d 00 73 00 69 00 75 00 74 00 69 00 6c 00 73 00 [0-16] 2e 00 67 00 65 00 74 00 66 00 69 00 65 00 6c 00 64 00 28 00 [0-16] 61 00 6d 00 73 00 69 00 63 00 6f 00 6e 00 74 00 65 00 78 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_PowerShell_Powdow_RRA_2147949457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Powdow.RRA!MTB"
        threat_id = "2147949457"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "102"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "iex" wide //weight: 1
        $x_1_3 = "hidden" wide //weight: 1
        $x_100_4 = {74 00 65 00 78 00 74 00 2e 00 65 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 5d 00 3a 00 3a 00 75 00 74 00 66 00 38 00 2e 00 67 00 65 00 74 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 5b 00 [0-31] 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 66 00 72 00 6f 00 6d 00 62 00 61 00 73 00 65 00 36 00 34 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 [0-5] 29 00 29 00 3b 00}  //weight: 100, accuracy: Low
        $x_100_5 = {3d 00 5b 00 63 00 68 00 61 00 72 00 5d 00 5b 00 63 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 54 00 6f 00 49 00 6e 00 74 00 33 00 32 00 28 00 24 00 [0-2] 2e 00 53 00 75 00 62 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 [0-2] 2c 00 32 00 29 00 2c 00 31 00 36 00 29 00 7d 00 7d 00 3b 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_1_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

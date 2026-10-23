rule Trojan_PowerShell_PsAttack_R_2147959148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/PsAttack.R"
        threat_id = "2147959148"
        type = "Trojan"
        platform = "PowerShell: "
        family = "PsAttack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "amsiutils" wide //weight: 10
        $x_10_2 = "amsiinitfailed" wide //weight: 10
        $x_1_3 = "getfield" wide //weight: 1
        $x_1_4 = "nonpublic,static" wide //weight: 1
        $x_1_5 = "setvalue" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_PsAttack_B_2147830457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/PsAttack.B"
        threat_id = "2147830457"
        type = "Trojan"
        platform = "PowerShell: "
        family = "PsAttack"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "yqbtahmaaqbjag4aaqb0aeyayqbpagwazqbkaa" wide //weight: 10
        $x_10_2 = "nonpublic,static" wide //weight: 10
        $x_10_3 = "setvalue($null,$true)" wide //weight: 10
        $x_10_4 = "[ref].assembly.gettype" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

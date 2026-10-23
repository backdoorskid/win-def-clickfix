rule Trojan_PowerShell_Sacepos_A_2147726214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Sacepos.A"
        threat_id = "2147726214"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Sacepos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks /create" wide //weight: 1
        $x_1_2 = "/sc onlogon" wide //weight: 1
        $x_1_3 = "/sc onstart" wide //weight: 1
        $x_1_4 = "/sc onidle" wide //weight: 1
        $x_10_5 = "IEX ((new-object net.webclient).downloadstring('" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

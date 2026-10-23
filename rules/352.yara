rule Trojan_PowerShell_DownInfo_C_2147933996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/DownInfo.C"
        threat_id = "2147933996"
        type = "Trojan"
        platform = "PowerShell: "
        family = "DownInfo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 00 70 00 73 00 68 00 6f 00 6d 00 65 00 5b 00 [0-4] 5d 00 2b 00 24 00 70 00 73 00 68 00 6f 00 6d 00 65 00 5b 00 [0-4] 5d 00 2b 00 27 00 78 00 27 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

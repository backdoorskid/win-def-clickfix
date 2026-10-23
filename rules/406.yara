rule Trojan_PowerShell_SuspLoadExec_ZI_2147972911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.ZI!MTB"
        threat_id = "2147972911"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 00 66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 [0-60] 24 00}  //weight: 1, accuracy: Low
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_3 = "} while ($" wide //weight: 1
        $x_1_4 = "]:::$???" wide //weight: 1
        $x_1_5 = "; do {$" wide //weight: 1
        $x_1_6 = ";while (!$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

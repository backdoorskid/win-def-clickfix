rule Trojan_PowerShell_SuspLoadExec_ZB_2147972906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.ZB!MTB"
        threat_id = "2147972906"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "join($a|%{-join($_.ToCharArray()|%" wide //weight: 1
        $x_1_2 = "IndexOf($_)+" wide //weight: 1
        $x_1_3 = "}:Unicode.GetString([Convert]::FromBase64String($" wide //weight: 1
        $x_1_4 = "})|iex" wide //weight: 1
        $x_1_5 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

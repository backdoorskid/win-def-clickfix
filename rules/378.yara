rule Trojan_PowerShell_Powdow_DF_2147961766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Powdow.DF!MTB"
        threat_id = "2147961766"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "curl -s http:/" wide //weight: 10
        $x_1_2 = "-o %temp%" wide //weight: 1
        $x_10_3 = ">nul &&" wide //weight: 10
        $x_10_4 = ":VBScript" wide //weight: 10
        $x_1_5 = "AppData\\Local\\Temp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_PowerShell_SuspLoadExec_ZG_2147972909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.ZG!MTB"
        threat_id = "2147972909"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String(" wide //weight: 1
        $x_1_2 = "System.Security.Cryptography" wide //weight: 1
        $x_1_3 = "WriteAllBytes(" wide //weight: 1
        $x_1_4 = "Shell.Application" wide //weight: 1
        $x_1_5 = "http" wide //weight: 1
        $x_1_6 = "GetTempPath(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

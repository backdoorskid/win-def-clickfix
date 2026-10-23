rule Trojan_PowerShell_SuspLoadExec_ZH_2147972910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.ZH!MTB"
        threat_id = "2147972910"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String(" wide //weight: 1
        $x_1_2 = "System.Security.Cryptography" wide //weight: 1
        $x_1_3 = "WriteAllBytes(" wide //weight: 1
        $x_1_4 = "Shell.Application" wide //weight: 1
        $x_1_5 = "http" wide //weight: 1
        $x_1_6 = "GetTempPath(" wide //weight: 1
        $x_1_7 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

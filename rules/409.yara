rule Trojan_PowerShell_SuspPosLoadz_ZB_2147972901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspPosLoadz.ZB!MTB"
        threat_id = "2147972901"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspPosLoadz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "&&set " ascii //weight: 1
        $x_1_2 = "--headless" ascii //weight: 1
        $x_1_3 = ";ge -f http" ascii //weight: 1
        $x_1_4 = "V:ON /c \"set" ascii //weight: 1
        $x_1_5 = "([string]$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

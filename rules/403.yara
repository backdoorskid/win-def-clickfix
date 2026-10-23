rule Trojan_PowerShell_SuspLoadExec_ZE_2147972907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.ZE!MTB"
        threat_id = "2147972907"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "if (Get-Process" wide //weight: 1
        $x_1_2 = "| Where-Object { $_.ProcessName -like" wide //weight: 1
        $x_1_3 = "irm \"http" wide //weight: 1
        $x_1_4 = "Get-Variable MaximumVariableCount).Attributes" wide //weight: 1
        $x_1_5 = "$_ -is [System.Management.Automation.ValidateRangeAttribute]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

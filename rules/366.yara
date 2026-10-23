rule Trojan_PowerShell_LummaStealer_AB_2147936312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/LummaStealer.AB!MTB"
        threat_id = "2147936312"
        type = "Trojan"
        platform = "PowerShell: "
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[PowerShell]::Create().AddScript" wide //weight: 1
        $x_1_2 = "[System.Net.WebClient]::New().DownloadString('http" wide //weight: 1
        $x_1_3 = ".Invoke()" wide //weight: 1
        $x_1_4 = ".xll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

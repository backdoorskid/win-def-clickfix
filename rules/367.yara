rule Trojan_PowerShell_LummaStealer_AC_2147936597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/LummaStealer.AC!MTB"
        threat_id = "2147936597"
        type = "Trojan"
        platform = "PowerShell: "
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[String]''.Chars" wide //weight: 1
        $x_1_2 = "[System.Net.WebClient]::New().DownloadString('http" wide //weight: 1
        $x_1_3 = "-Join" wide //weight: 1
        $x_1_4 = ".xll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

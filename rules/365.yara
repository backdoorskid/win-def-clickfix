rule Trojan_PowerShell_LummaStealer_BE_2147936043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/LummaStealer.BE!MTB"
        threat_id = "2147936043"
        type = "Trojan"
        platform = "PowerShell: "
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Security.Cryptography.Aes]::Create()).CreateDecryptor" wide //weight: 1
        $x_1_2 = "[byte[]]::new(16)).TransformFinalBlock" wide //weight: 1
        $x_1_3 = ".Substring(0,3)" wide //weight: 1
        $x_1_4 = "-w h -ep" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

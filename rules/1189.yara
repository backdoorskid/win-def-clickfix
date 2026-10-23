rule Trojan_Win32_PowExcEnv_H_2147946382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.H!MTB"
        threat_id = "2147946382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Add-MpPreference" wide //weight: 1
        $x_1_2 = "-exclusion" wide //weight: 1
        $x_1_3 = "$env:" wide //weight: 1
        $x_1_4 = "appdata" wide //weight: 1
        $x_1_5 = "-replace" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

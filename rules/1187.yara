rule Trojan_Win32_PowExcEnv_ZA_2147943072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.ZA!MTB"
        threat_id = "2147943072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "add-mppreference -exclusionpath $" wide //weight: 1
        $x_1_2 = "add-mppreference -exclusionprocess $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

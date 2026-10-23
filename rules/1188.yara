rule Trojan_Win32_PowExcEnv_ZB_2147943074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.ZB!MTB"
        threat_id = "2147943074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "add-mppreference -exclusionpath $" wide //weight: 1
        $x_1_2 = "add-mppreference -exclusionprocess $" wide //weight: 1
        $x_1_3 = "foreach ($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

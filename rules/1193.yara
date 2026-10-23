rule Trojan_Win32_PowExcEnv_G_2147957029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowExcEnv.G!MTB"
        threat_id = "2147957029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowExcEnv"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Powershell" wide //weight: 1
        $x_1_2 = "add-mppreference" wide //weight: 1
        $x_1_3 = "-exclusionpath" wide //weight: 1
        $x_1_4 = "$env:USERPROFILE" wide //weight: 1
        $x_1_5 = "appdata" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

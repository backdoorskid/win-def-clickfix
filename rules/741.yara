rule Trojan_Win32_DarkShadowWiper_C_2147775453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DarkShadowWiper.C!dha"
        threat_id = "2147775453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DarkShadowWiper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "schtasks" wide //weight: 1
        $x_1_2 = "/create" wide //weight: 1
        $x_1_3 = "CrashHandlerUAC" wide //weight: 1
        $n_10_4 = "/disable" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

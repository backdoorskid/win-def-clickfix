rule Trojan_Win32_WhoAmiExit_MK_2147948213_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/WhoAmiExit.MK"
        threat_id = "2147948213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "WhoAmiExit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sb_" wide //weight: 1
        $x_1_2 = "_bs >nul" wide //weight: 1
        $x_1_3 = "whoami & exit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

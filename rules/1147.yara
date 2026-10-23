rule Trojan_Win32_Powdow_ABF_2147967917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powdow.ABF!MTB"
        threat_id = "2147967917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_1_2 = "-join[char[]" wide //weight: 1
        $x_2_3 = "//:sptth" wide //weight: 2
        $x_1_4 = "-replace" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspLoad_BE_2147980388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLoad.BE!MTB"
        threat_id = "2147980388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "; powershell" wide //weight: 1
        $x_1_2 = ".replace(' ',$" wide //weight: 1
        $x_1_3 = "-replace" wide //weight: 1
        $x_1_4 = "]::FromBase64String( $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

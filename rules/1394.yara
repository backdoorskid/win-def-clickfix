rule Trojan_Win32_SupsPost_ZF_2147979647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZF!MTB"
        threat_id = "2147979647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[array]::Reverse($" wide //weight: 10
        $x_10_2 = ".ToCharArray();" wide //weight: 10
        $x_1_3 = "|iex" wide //weight: 1
        $x_1_4 = "|invoke-expression" wide //weight: 1
        $x_1_5 = ";iex" wide //weight: 1
        $x_1_6 = ";invoke-expression" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

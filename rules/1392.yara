rule Trojan_Win32_SupsPost_ZE_2147979646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZE!MTB"
        threat_id = "2147979646"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Convert]::FromBase64String([regex]::Replace($" wide //weight: 1
        $x_1_2 = "[char]($" wide //weight: 1
        $x_1_3 = "bxor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

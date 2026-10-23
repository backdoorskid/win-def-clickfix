rule Trojan_Win32_SupsPost_ZD_2147979643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZD!MTB"
        threat_id = "2147979643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[byte][char]$" wide //weight: 1
        $x_1_2 = ";iEx $" wide //weight: 1
        $x_1_3 = "[Convert]::FromBase64String(" ascii //weight: 1
        $x_1_4 = "-bxor" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

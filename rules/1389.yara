rule Trojan_Win32_SupsPost_ZC_2147979641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SupsPost.ZC!MTB"
        threat_id = "2147979641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SupsPost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[Reflection.Assembly]::Load(" wide //weight: 1
        $x_1_2 = "[Convert]::ToString($" wide //weight: 1
        $x_1_3 = "-bxor $" wide //weight: 1
        $x_1_4 = "[Reflection.BindingFlags]" wide //weight: 1
        $x_1_5 = ".Invoke($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

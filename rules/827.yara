rule Trojan_Win32_FileFix_HHB_2147950080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHB!MTB"
        threat_id = "2147950080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "::WriteAllBytes;$" wide //weight: 1
        $x_1_2 = "::ReadAllBytes;$" wide //weight: 1
        $x_1_3 = "[System.Convert];$" wide //weight: 1
        $x_1_4 = ".GetBytes;$" wide //weight: 1
        $x_1_5 = ":FromBase64String;$" wide //weight: 1
        $x_1_6 = "GetString;$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ClixkFix_NS_2147978274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ClixkFix.NS!MTB"
        threat_id = "2147978274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ClixkFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-Headers @{(" wide //weight: 1
        $x_1_2 = "-UserAgent " wide //weight: 1
        $x_1_3 = "|iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

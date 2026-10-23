rule Trojan_Win32_SuspIex_C_2147980385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspIex.C!MTB"
        threat_id = "2147980385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspIex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "irm 'http" wide //weight: 1
        $x_1_2 = "'|iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

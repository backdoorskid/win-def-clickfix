rule Trojan_Win32_SuspIex_B_2147980381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspIex.B!MTB"
        threat_id = "2147980381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspIex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "irm '0x" wide //weight: 1
        $x_1_2 = "| iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

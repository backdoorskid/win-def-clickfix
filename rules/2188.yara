rule Trojan_Win64_ClickFix_GVL_2147965625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ClickFix.GVL!MTB"
        threat_id = "2147965625"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ClickFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Start-Process" wide //weight: 10
        $x_10_2 = "|cmd" wide //weight: 10
        $x_10_3 = "finger Galo" wide //weight: 10
        $x_10_4 = "-WindowStyle Hidden" wide //weight: 10
        $x_10_5 = "Verify" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

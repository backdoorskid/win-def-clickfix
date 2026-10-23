rule Trojan_Win32_MshtaUrsnif_C_2147756289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MshtaUrsnif.C"
        threat_id = "2147756289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MshtaUrsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "310"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "new ActiveXObject" wide //weight: 100
        $x_100_2 = ".RegRead" wide //weight: 100
        $x_100_3 = {48 00 4b 00 43 00 55 00 [0-4] 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00}  //weight: 100, accuracy: Low
        $x_10_4 = "eval" wide //weight: 10
        $x_10_5 = "'e'+'val'" wide //weight: 10
        $x_10_6 = "'ev'+'al'" wide //weight: 10
        $x_10_7 = "'eva'+'l'" wide //weight: 10
        $x_10_8 = "'e'+'v'+'al'" wide //weight: 10
        $x_10_9 = "'e'+'va'+'l'" wide //weight: 10
        $x_10_10 = "'ev'+'a'+'l'" wide //weight: 10
        $x_10_11 = "'e'+'v'+'a'+'l'" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

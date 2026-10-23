rule Trojan_Win32_Meshtarl_B_2147763034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meshtarl.B"
        threat_id = "2147763034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meshtarl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-240] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-240] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_4 = {66 00 74 00 70 00 3a 00 2f 00 2f 00 [0-240] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

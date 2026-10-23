rule Trojan_Win32_Dexphot_CD_2147735856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dexphot.CD"
        threat_id = "2147735856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dexphot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 2d 00 69 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 [0-32] 2f 00 69 00 [0-16] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $n_10_3 = "www.zoom.us" ascii //weight: -10
        $n_10_4 = "powershell" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

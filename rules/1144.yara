rule Trojan_Win32_Powdow_HD_2147951098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powdow.HD!MTB"
        threat_id = "2147951098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powdow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "252"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {27 00 2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 27 00 [0-16] 27 00 2c 00 27 00 27 00 29 00 29 00 29 00 29 00}  //weight: 50, accuracy: Low
        $x_200_2 = {63 00 67 00 62 00 6a 00 61 00 67 00 34 00 61 00 64 00 67 00 62 00 76 00 61 00 67 00 73 00 [0-16] 61 00 7a 00 71 00 61 00 74 00 61 00 65 00 75 00 61 00 65 00 61 00 62 00 77 00 61 00 68 00 00}  //weight: 200, accuracy: Low
        $x_1_3 = "frombase64string" wide //weight: 1
        $x_1_4 = "iex(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Astaroth_KH_2147919968_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Astaroth.KH"
        threat_id = "2147919968"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mshta " wide //weight: 1
        $x_1_2 = "javascript:var " wide //weight: 1
        $x_1_3 = {74 00 72 00 79 00 [0-4] 67 00 65 00 74 00 6f 00 62 00 6a 00 65 00 63 00 74 00 [0-255] 63 00 61 00 74 00 63 00 68 00 28 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

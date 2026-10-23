rule TrojanDownloader_Win64_ClickFix_CURL_2147977558_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/ClickFix.CURL"
        threat_id = "2147977558"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c^u^r^l" wide //weight: 1
        $x_1_2 = "c^u^rl" wide //weight: 1
        $x_1_3 = "c^ur^l" wide //weight: 1
        $x_1_4 = "cu^r^l" wide //weight: 1
        $x_1_5 = "c^url" wide //weight: 1
        $x_1_6 = "cu^rl" wide //weight: 1
        $x_1_7 = "cur^l" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_MshtaAbuse_C_2147811629_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/MshtaAbuse.C"
        threat_id = "2147811629"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "MshtaAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta http://" wide //weight: 1
        $x_1_2 = "mshta https://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

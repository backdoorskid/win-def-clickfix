rule TrojanDownloader_Win32_MshtaAbuse_A_2147811392_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/MshtaAbuse.A"
        threat_id = "2147811392"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "MshtaAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = "http://0x" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

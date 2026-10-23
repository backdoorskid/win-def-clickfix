rule TrojanDownloader_PowerShell_LodPey_A_2147777715_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:PowerShell/LodPey.A"
        threat_id = "2147777715"
        type = "TrojanDownloader"
        platform = "PowerShell: "
        family = "LodPey"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 65 00 76 00 32 00 30 00 31 00 2e 00 63 00 64 00 6e 00 69 00 6d 00 61 00 67 00 65 00 73 00 2e 00 78 00 79 00 7a 00 3a 00 38 00 30 00 2f 00 15 00 2f 00 15 00 27 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

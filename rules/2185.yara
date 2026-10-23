rule Ransom_Win64_Dopplepaymer_C_2147745558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Dopplepaymer.C"
        threat_id = "2147745558"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Dopplepaymer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " -Command " wide //weight: 1
        $x_1_2 = ".DownloadFile('http://eltrade.ro/lucru" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

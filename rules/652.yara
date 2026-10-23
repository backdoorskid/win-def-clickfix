rule Trojan_Win32_Ceprolad_A_2147726914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ceprolad.A"
        threat_id = "2147726914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ceprolad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "112"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "certutil" wide //weight: 100
        $x_1_2 = "-urlcache" wide //weight: 1
        $x_1_3 = "/urlcache" wide //weight: 1
        $x_1_4 = " -f " wide //weight: 1
        $x_1_5 = " /f " wide //weight: 1
        $x_10_6 = " ftp://" wide //weight: 10
        $n_50_7 = {6b 00 65 00 72 00 62 00 65 00 72 00 6f 00 73 00 20 00 [0-32] 63 00 6f 00 6e 00 66 00 69 00 67 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: -50, accuracy: Low
        $n_50_8 = "http://crl.pki.va.gov/" wide //weight: -50
        $n_50_9 = "http://http.fpki.gov/" wide //weight: -50
        $n_50_10 = "https://crl.pki.va.gov/" wide //weight: -50
        $n_50_11 = "https://http.fpki.gov/" wide //weight: -50
        $n_50_12 = "https://ss64.com" wide //weight: -50
        $n_50_13 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 2f 00 61 00 62 00 62 00 [0-255] 2e 00 63 00 72 00 6c 00}  //weight: -50, accuracy: Low
        $n_50_14 = "https://transparency.michigan.gov" wide //weight: -50
        $n_50_15 = "http://localhost/fio-62833e7bae788a6973cdf8d5.crl" wide //weight: -50
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_BastaLoader_SA_2147847880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BastaLoader.SA"
        threat_id = "2147847880"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BastaLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32" wide //weight: 1
        $x_10_2 = ".dll,visibleentry" wide //weight: 10
        $n_100_3 = "davsetcookie" wide //weight: -100
        $n_100_4 = "hgsportalsetupx86_c" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

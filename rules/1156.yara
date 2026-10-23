rule Trojan_Win32_Powemet_K_2147788208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.K!attk"
        threat_id = "2147788208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $n_100_1 = ".dll" wide //weight: -100
        $x_10_2 = "regsvr32" wide //weight: 10
        $x_1_3 = ".jpg" wide //weight: 1
        $x_1_4 = ".csv" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RundllLolBin_AG_2147795800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AG"
        threat_id = "2147795800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bitsadmin.exe" wide //weight: 1
        $x_1_2 = "transfer" wide //weight: 1
        $x_1_3 = "https" wide //weight: 1
        $x_1_4 = ".xls" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RundllLolBin_AC_2147787820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AC"
        threat_id = "2147787820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" wide //weight: 1
        $x_1_2 = "javascript" wide //weight: 1
        $x_1_3 = "RunHTMLApplication" wide //weight: 1
        $x_1_4 = ".exec(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

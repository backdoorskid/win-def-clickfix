rule Trojan_Win32_RundllLolBin_AE_2147788905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AE"
        threat_id = "2147788905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" wide //weight: 1
        $x_1_2 = "javascript" wide //weight: 1
        $x_1_3 = "RunHTMLApplication" wide //weight: 1
        $x_1_4 = ".run" wide //weight: 1
        $x_1_5 = "wscript.shell" wide //weight: 1
        $x_1_6 = "eval(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

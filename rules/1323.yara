rule Trojan_Win32_RundllLolBin_AF_2147793100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AF"
        threat_id = "2147793100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "lsass" wide //weight: 1
        $x_1_3 = "rundll32" wide //weight: 1
        $x_1_4 = "MiniDump" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

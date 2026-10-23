rule Trojan_Win32_MshtaLolBin_B_2147812975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MshtaLolBin.B"
        threat_id = "2147812975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MshtaLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta.exe" wide //weight: 1
        $x_1_2 = "javascript" wide //weight: 1
        $x_1_3 = "activexobject" wide //weight: 1
        $x_1_4 = "wscript.shell" wide //weight: 1
        $x_1_5 = ".run(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

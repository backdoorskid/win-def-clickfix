rule Trojan_Win32_Nibtse_A_2147734631_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nibtse.A"
        threat_id = "2147734631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nibtse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 [0-5] 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = "mshta vbscript:CreateObject" wide //weight: 1
        $x_1_3 = ".Run(" wide //weight: 1
        $x_1_4 = "//pastebin.com/raw/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

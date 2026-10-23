rule Trojan_Win32_Powessere_O_2147772335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.O"
        threat_id = "2147772335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "javascript:" wide //weight: 1
        $x_1_3 = "ActiveXObject(" wide //weight: 1
        $x_1_4 = "wscript.shell" wide //weight: 1
        $x_1_5 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 48 00 4b 00 43 00 55 00 5c 00 [0-4] 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_6 = ";eval(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

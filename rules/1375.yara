rule Trojan_Win32_Socgolsh_SI_2147919880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SI"
        threat_id = "2147919880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 79 00 74 00 68 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00 2f 00 66 00 74 00 70 00 [0-255] 2e 00 7a 00 69 00 70 00 20 00}  //weight: 1, accuracy: Low
        $x_1_3 = "-literalpath" wide //weight: 1
        $x_1_4 = "-destinationpath" wide //weight: 1
        $x_1_5 = " https://bootstrap.pypa.io/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

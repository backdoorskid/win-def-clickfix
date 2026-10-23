rule Trojan_Win32_Socgolsh_SF_2147916063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SF"
        threat_id = "2147916063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_10_2 = {77 00 67 00 65 00 74 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 79 00 74 00 68 00 6f 00 6e 00 2e 00 6f 00 72 00 67 00 2f 00 66 00 74 00 70 00 [0-255] 2e 00 7a 00 69 00 70 00 20 00 2d 00 6f 00 75 00 74 00 66 00 69 00 6c 00 65 00 20 00}  //weight: 10, accuracy: Low
        $x_1_3 = ".zip;ls" wide //weight: 1
        $x_10_4 = ".zip;expand-archive -literalpath" wide //weight: 10
        $x_10_5 = {7a 00 69 00 70 00 [0-16] 2d 00 64 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00}  //weight: 10, accuracy: Low
        $x_1_6 = " https://bootstrap.pypa.io/get-pip.py" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

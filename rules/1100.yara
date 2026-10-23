rule Trojan_Win32_Ofisus_B_2147734551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.B"
        threat_id = "2147734551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00 43 00 3a 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 20 00 68 00 74 00 74 00 70 00}  //weight: 2, accuracy: High
        $x_2_2 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00 6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00}  //weight: 2, accuracy: High
        $x_1_3 = ".hta" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

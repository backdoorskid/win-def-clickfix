rule Trojan_Win32_Powessere_H_2147726088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.H"
        threat_id = "2147726088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = {41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 22 00 57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 22 00 29 00 3b 00 [0-32] 3d 00 22 00 [0-32] 22 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 22 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 [0-32] 5c 00 5c 00 [0-32] 22 00 29 00 3b 00 [0-32] 3d 00 22 00 [0-32] 22 00 3b 00 65 00 76 00 61 00 6c 00 28 00 [0-32] 29 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 22 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 [0-32] 5c 00 5c 00 [0-32] 22 00 29 00 3b 00 [0-32] 3d 00 22 00 [0-32] 22 00 3b 00 74 00 68 00 69 00 73 00 5b 00 27 00 65 00 76 00 27 00 2b 00 27 00 61 00 6c 00 27 00 5d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

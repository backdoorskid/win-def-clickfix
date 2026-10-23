rule Trojan_Win32_Kovter_R_2147740356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kovter.R!cmd"
        threat_id = "2147740356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kovter"
        severity = "Critical"
        info = "cmd: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\mshta.exe" wide //weight: 1
        $x_1_2 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-48] 3d 00 6e 00 65 00 77 00 20 00 61 00 63 00 74 00 69 00 76 00 65 00 78 00 6f 00 62 00 6a 00 65 00 63 00 74 00 28 00 [0-4] 77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 00 72 00 65 00 67 00 72 00 65 00 61 00 64 00 28 00 [0-4] 68 00 6b 00 63 00 75 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = ";eval(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

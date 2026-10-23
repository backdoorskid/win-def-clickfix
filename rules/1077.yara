rule Trojan_Win32_NtdsExfil_B_2147777153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NtdsExfil.B"
        threat_id = "2147777153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NtdsExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd /c" wide //weight: 1
        $x_1_2 = "cmd.exe /c" wide //weight: 1
        $x_2_3 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 63 00 72 00 65 00 61 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 [0-16] 66 00 6f 00 72 00 3d 00 43 00 3a 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

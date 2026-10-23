rule Trojan_Win32_Socgolsh_SC_2147909962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SC"
        threat_id = "2147909962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "wget https://www.python.org/ftp" wide //weight: 1
        $x_1_3 = ".zip;expand-archive -literalpath" wide //weight: 1
        $x_1_4 = {2d 00 64 00 65 00 73 00 74 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 70 00 61 00 74 00 68 00 [0-255] 5c 00 70 00 79 00 33 00 3b 00 64 00 65 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_5 = {7a 00 69 00 70 00 3b 00 6c 00 73 00 [0-255] 5c 00 70 00 79 00 33 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

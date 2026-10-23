rule Trojan_Win32_Socgolsh_SCA_2147937797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SCA"
        threat_id = "2147937797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 [0-16] 2f 00 63 00}  //weight: 1, accuracy: Low
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = "expand-archive" wide //weight: 1
        $x_1_4 = "-literalpath" wide //weight: 1
        $x_1_5 = "-destinationpath" wide //weight: 1
        $x_1_6 = "python" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

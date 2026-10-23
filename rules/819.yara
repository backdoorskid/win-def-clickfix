rule Trojan_Win32_FileFix_DI_2147946487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.DI!MTB"
        threat_id = "2147946487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = {2d 00 63 00 20 00 70 00 69 00 6e 00 67 00 [0-80] 23 00}  //weight: 10, accuracy: Low
        $x_1_3 = ".docx" wide //weight: 1
        $x_1_4 = ".pdf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FileFix_HB_2147947995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HB!MTB"
        threat_id = "2147947995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "106"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {2e 00 65 00 78 00 65 00 23 15 15 03 27 29 20 23 00 20 00}  //weight: 100, accuracy: Low
        $x_100_2 = {2e 00 70 00 73 00 31 00 23 15 15 03 27 29 20 23 00 20 00}  //weight: 100, accuracy: Low
        $x_5_3 = "curl " wide //weight: 5
        $x_5_4 = "powershell" wide //weight: 5
        $x_1_5 = " http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_5_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

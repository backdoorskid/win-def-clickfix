rule Trojan_Win32_SuspClickFix_H_2147943617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.H"
        threat_id = "2147943617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " cmd.exe /c cmd.exe /c " wide //weight: 1
        $x_1_3 = "POST" wide //weight: 1
        $x_1_4 = "http" wide //weight: 1
        $x_1_5 = ".php" wide //weight: 1
        $x_1_6 = " -o " wide //weight: 1
        $x_1_7 = "&& start " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

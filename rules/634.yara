rule Trojan_Win32_BITSAbuse_D_2147731551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BITSAbuse.D"
        threat_id = "2147731551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BITSAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 [0-32] 2f 00 63 00}  //weight: 1, accuracy: Low
        $x_1_2 = {62 00 69 00 74 00 73 00 61 00 64 00 6d 00 69 00 6e 00 [0-16] 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_3 = "certutil -decode" wide //weight: 1
        $x_1_4 = {73 00 74 00 61 00 72 00 74 00 [0-240] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

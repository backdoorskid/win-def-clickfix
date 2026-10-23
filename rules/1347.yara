rule Trojan_Win32_SchExec_HN_2147951100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SchExec.HN!MTB"
        threat_id = "2147951100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SchExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "schtasks /create" wide //weight: 1
        $x_10_2 = {5c 00 66 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 [0-18] 5c 00 6d 00 73 00 62 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 72 00 6c 00 20 00 68 00 69 00 67 00 68 00 65 00 73 00 74 00 20 00 2f 00 66 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

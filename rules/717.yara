rule Trojan_Win32_CopyRemot_C_2147942056_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CopyRemot.C"
        threat_id = "2147942056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CopyRemot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd /c copy /b" wide //weight: 1
        $x_1_2 = {2e 00 76 00 73 00 73 00 20 00 2b 00 [0-60] 2e 00 76 00 73 00 73 00 20 00 2b 00 [0-60] 2e 00 76 00 73 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

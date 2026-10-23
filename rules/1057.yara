rule Trojan_Win32_NetworkConfig_C_2147766430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetworkConfig.C!pwsh"
        threat_id = "2147766430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetworkConfig"
        severity = "Critical"
        info = "pwsh: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 00 69 00 6e 00 33 00 32 00 5f 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 61 00 64 00 61 00 70 00 74 00 65 00 72 00 63 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 [0-64] 2d 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

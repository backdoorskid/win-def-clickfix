rule Trojan_Win32_SuspProxyExecution_C_2147938108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxyExecution.C"
        threat_id = "2147938108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxyExecution"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "& powershell.exe control.exe" ascii //weight: 1
        $x_1_2 = {5c 00 74 00 65 00 6d 00 70 00 5c 00 [0-143] 2e 00 63 00 70 00 6c 00 20 00 26 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 74 65 6d 70 5c [0-143] 2e 63 70 6c 20 26}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_FileFix_HHC_2147950081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHC!MTB"
        threat_id = "2147950081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 61 00 73 00 70 00 78 00 [0-60] 20 00 23 00}  //weight: 1, accuracy: Low
        $x_1_2 = "Start-Process http" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

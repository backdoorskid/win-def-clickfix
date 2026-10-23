rule Trojan_Win32_FileFix_HHI_2147950721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.HHI!MTB"
        threat_id = "2147950721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netsh wlan" wide //weight: 1
        $x_1_2 = "curl" wide //weight: 1
        $x_1_3 = "telegram" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

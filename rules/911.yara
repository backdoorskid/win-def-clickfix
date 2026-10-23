rule Trojan_Win32_LummaStealerClick_Q_2147932741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.Q!MTB"
        threat_id = "2147932741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = "-Join" wide //weight: 1
        $x_1_4 = "I`E`X" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

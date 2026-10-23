rule Trojan_Win32_LummaStealerClick_K_2147932423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.K"
        threat_id = "2147932423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "hidden" wide //weight: 1
        $x_1_3 = "iwr http" wide //weight: 1
        $x_1_4 = ".ps1 | iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

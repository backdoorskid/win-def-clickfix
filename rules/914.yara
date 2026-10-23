rule Trojan_Win32_LummaStealerClick_T_2147933214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.T!MTB"
        threat_id = "2147933214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "51"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell" wide //weight: 10
        $x_10_2 = "http" wide //weight: 10
        $x_10_3 = "pastebin.com/raw" wide //weight: 10
        $x_10_4 = "net.webclient" wide //weight: 10
        $x_10_5 = "download" wide //weight: 10
        $x_1_6 = ".exe" wide //weight: 1
        $x_1_7 = ".dll" wide //weight: 1
        $x_1_8 = ".ps1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

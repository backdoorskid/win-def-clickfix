rule Trojan_Win32_LummaStealerClick_W_2147935084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.W!MTB"
        threat_id = "2147935084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http" wide //weight: 10
        $x_10_2 = "php?action" wide //weight: 10
        $x_1_3 = "iex" wide //weight: 1
        $x_1_4 = "invoke-expression" wide //weight: 1
        $x_1_5 = "iwr" wide //weight: 1
        $x_1_6 = "invoke-webrequest" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

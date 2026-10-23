rule Trojan_Win32_LummaStealerClick_U_2147934654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.U!MTB"
        threat_id = "2147934654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "add-mppreference" wide //weight: 1
        $x_1_3 = "-exclusion" wide //weight: 1
        $x_1_4 = "$env:" wide //weight: 1
        $x_1_5 = "net.webclient" wide //weight: 1
        $x_1_6 = ".download" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

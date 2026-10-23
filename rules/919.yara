rule Trojan_Win32_LummaStealerClick_Y_2147935504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.Y!MTB"
        threat_id = "2147935504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net.webclient" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = ".name" wide //weight: 1
        $x_1_4 = "Get-Member" wide //weight: 1
        $x_1_5 = "value" wide //weight: 1
        $x_1_6 = ").Invoke" wide //weight: 1
        $x_1_7 = "Where{(Variable" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

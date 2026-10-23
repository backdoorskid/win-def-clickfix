rule Trojan_Win32_LummaStealerClick_V_2147935083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.V!MTB"
        threat_id = "2147935083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net.webclient" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = ".name" wide //weight: 1
        $x_1_4 = "psobject.methods" wide //weight: 1
        $x_1_5 = "value" wide //weight: 1
        $x_1_6 = ").Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

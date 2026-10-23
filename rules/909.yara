rule Trojan_Win32_LummaStealerClick_AB_2147932739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.AB!MTB"
        threat_id = "2147932739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net.webclient" wide //weight: 1
        $x_1_2 = "http" wide //weight: 1
        $x_1_3 = ".name" wide //weight: 1
        $x_1_4 = ".invokecommand|get-member|where{" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

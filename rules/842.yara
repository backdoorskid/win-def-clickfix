rule Trojan_Win32_GlassWorm_MKG_2147972535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/GlassWorm.MKG!MTB"
        threat_id = "2147972535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "GlassWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-Command" wide //weight: 1
        $x_1_3 = "irm" wide //weight: 1
        $x_1_4 = "https:" wide //weight: 1
        $x_1_5 = ".lat" wide //weight: 1
        $x_1_6 = "i/_" wide //weight: 1
        $x_1_7 = "| iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

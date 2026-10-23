rule Trojan_Win32_LummaStealerClick_X_2147935729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealerClick.X!MTB"
        threat_id = "2147935729"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealerClick"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "net.webclient" wide //weight: 10
        $x_10_2 = "reflection.assembly]::load($" wide //weight: 10
        $x_10_3 = ".invoke($" wide //weight: 10
        $x_10_4 = ".Convert]::FromBase64String($" wide //weight: 10
        $x_10_5 = ".GetMethod(" wide //weight: 10
        $x_10_6 = "http" wide //weight: 10
        $x_10_7 = ".DownloadData($" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_PSDown_BSB_2147943453_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/PSDown.BSB!MTB"
        threat_id = "2147943453"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "PSDown"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "([system.Convert]::FromBase64String($" wide //weight: 1
        $x_1_2 = ".Net.WebClient" wide //weight: 1
        $x_1_3 = ".DownloadData(" wide //weight: 1
        $x_1_4 = "[regex]::split($" wide //weight: 1
        $x_1_5 = "Invoke(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

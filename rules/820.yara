rule Trojan_Win32_FileFix_DJ_2147947112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.DJ!MTB"
        threat_id = "2147947112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".Headers.Add(" wide //weight: 10
        $x_10_2 = ".DownloadString(" wide //weight: 10
        $x_10_3 = "Net.WebClient" wide //weight: 10
        $x_10_4 = "| iex" wide //weight: 10
        $x_10_5 = "schtasks /delete" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

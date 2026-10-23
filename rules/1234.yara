rule Trojan_Win32_PShellDlr_HH_2147947711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.HH!MTB"
        threat_id = "2147947711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "53"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[scriptblock]::create(" wide //weight: 1
        $x_1_2 = "invoke-restmethod $" wide //weight: 1
        $x_1_3 = ".invoke()" wide //weight: 1
        $x_40_4 = "[int][char]$_" wide //weight: 40
        $x_10_5 = "-join ''" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

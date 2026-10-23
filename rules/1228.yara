rule Trojan_Win32_PShellDlr_YM_2147939370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.YM!MTB"
        threat_id = "2147939370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "-split" wide //weight: 10
        $x_10_2 = "char]([convert]::ToInt32($_" wide //weight: 10
        $x_10_3 = "powershell" wide //weight: 10
        $x_10_4 = "-join" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

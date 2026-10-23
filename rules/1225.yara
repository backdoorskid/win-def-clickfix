rule Trojan_Win32_PShellDlr_SF_2147937009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellDlr.SF!MTB"
        threat_id = "2147937009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellDlr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1051"
        strings_accuracy = "High"
    strings:
        $x_500_1 = "powershell" wide //weight: 500
        $x_500_2 = "net.webclient" wide //weight: 500
        $x_50_3 = "invoke" wide //weight: 50
        $x_50_4 = "Create().AddScript(" wide //weight: 50
        $x_50_5 = " iwr" wide //weight: 50
        $x_1_6 = ".shop" wide //weight: 1
        $x_1_7 = ".xyz" wide //weight: 1
        $x_1_8 = ".cyou" wide //weight: 1
        $x_1_9 = ".click" wide //weight: 1
        $x_1_10 = ".online" wide //weight: 1
        $x_1_11 = ".today" wide //weight: 1
        $x_1_12 = ".lat" wide //weight: 1
        $x_1_13 = ".icu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_500_*) and 1 of ($x_50_*) and 1 of ($x_1_*))) or
            ((2 of ($x_500_*) and 2 of ($x_50_*))) or
            (all of ($x*))
        )
}

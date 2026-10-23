rule Trojan_Win32_RevShell_MUA_2147979871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RevShell.MUA!MTB"
        threat_id = "2147979871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "(get-date).addseconds(" wide //weight: 10
        $x_10_2 = ".connectasync(" wide //weight: 10
        $x_10_3 = {6e 00 65 00 74 00 2e 00 73 00 6f 00 63 00 6b 00 65 00 74 00 73 00 2e 00 74 00 63 00 70 00 63 00 6c 00 69 00 65 00 6e 00 74 00 [0-255] 2e 00 67 00 65 00 74 00 73 00 74 00 72 00 65 00 61 00 6d 00 28 00 29 00}  //weight: 10, accuracy: Low
        $x_10_4 = ".streamwriter(" wide //weight: 10
        $x_1_5 = "invoke-expression" wide //weight: 1
        $x_1_6 = "iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Powessere_SA_2147817497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.SA"
        threat_id = "2147817497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "415"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "powershell.exe" wide //weight: 100
        $x_100_2 = "[system.text.encoding]::ascii.getstring" wide //weight: 100
        $x_100_3 = {68 00 6b 00 [0-4] 3a 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 [0-32] 29 00 2e 00 [0-32] 29 00}  //weight: 100, accuracy: Low
        $x_100_4 = "[system.convert]::frombase64string" wide //weight: 100
        $x_10_5 = "iex" wide //weight: 10
        $x_10_6 = "invoke-expression" wide //weight: 10
        $x_5_7 = "get-itemproperty " wide //weight: 5
        $x_5_8 = "gp " wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((4 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

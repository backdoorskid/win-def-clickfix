rule Trojan_Win32_Powessere_K_2147734747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.K"
        threat_id = "2147734747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_2_2 = "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\\Software\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

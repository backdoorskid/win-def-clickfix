rule Trojan_Win32_Powessere_M_2147740997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.M"
        threat_id = "2147740997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "(Get-ItemProperty" wide //weight: 1
        $x_1_3 = {72 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 3a 00 3a 00 48 00 4b 00 ?? ?? ?? ?? 5c 00 5c 00 53 00 3f 00 3f 00 3f 00 77 00 61 00 72 00 65 00 5c 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = "iex" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

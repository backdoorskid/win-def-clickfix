rule Trojan_Win32_Powessere_S_2147793327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.S"
        threat_id = "2147793327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "/Create" wide //weight: 1
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "::FromBase64String(" wide //weight: 1
        $x_1_5 = {28 00 67 00 70 00 20 00 [0-2] 48 00 4b 00 ?? ?? ?? ?? 3a 00 5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

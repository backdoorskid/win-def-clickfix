rule Trojan_Win32_SuspClickFix_C_2147941554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.C"
        threat_id = "2147941554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_5_2 = "iwr " wide //weight: 5
        $x_1_3 = "iex $" wide //weight: 1
        $x_1_4 = "| iex" wide //weight: 1
        $x_1_5 = "|iex" wide //weight: 1
        $x_1_6 = ";iex " wide //weight: 1
        $x_1_7 = "iex(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

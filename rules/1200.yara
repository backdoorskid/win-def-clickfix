rule Trojan_Win32_Priteshel_A_2147783751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Priteshel.A"
        threat_id = "2147783751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Priteshel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "New-Object" wide //weight: 1
        $x_1_3 = "Net.Webclient" wide //weight: 1
        $x_1_4 = ".downloadstring" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

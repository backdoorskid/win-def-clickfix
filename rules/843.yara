rule Trojan_Win32_Goptaju_B_2147959419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Goptaju.B"
        threat_id = "2147959419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Goptaju"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "invoke-restmethod" wide //weight: 1
        $x_1_2 = "iex" wide //weight: 1
        $x_1_3 = "-uri" wide //weight: 1
        $x_1_4 = ").replace(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

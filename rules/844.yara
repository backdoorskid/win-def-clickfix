rule Trojan_Win32_Goptaju_D_2147959420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Goptaju.D"
        threat_id = "2147959420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Goptaju"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "iex" wide //weight: 10
        $x_1_2 = "new-object system.net.webclient" wide //weight: 1
        $x_1_3 = ".downloadstring(" wide //weight: 1
        $x_1_4 = ".ps1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

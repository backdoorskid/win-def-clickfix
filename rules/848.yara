rule Trojan_Win32_Goptaju_E_2147959535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Goptaju.E"
        threat_id = "2147959535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Goptaju"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "iex" wide //weight: 10
        $x_1_2 = "new-object system.net.webclient" wide //weight: 1
        $x_1_3 = ".downloadstring(" wide //weight: 1
        $n_1_4 = "validated_work_needed" wide //weight: -1
        $n_1_5 = "chocolatey" wide //weight: -1
        $n_1_6 = "msp360" wide //weight: -1
        $n_1_7 = "hcpss" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

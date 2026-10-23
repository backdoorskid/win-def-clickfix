rule Trojan_Win32_SuspAAD_B_2147954136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspAAD.B"
        threat_id = "2147954136"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspAAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WMIObject Win32_NTDomain" ascii //weight: 1
        $x_1_3 = "findstr DomainController" ascii //weight: 1
        $n_1_4 = "69802c98-2ce2-4a17-98v0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

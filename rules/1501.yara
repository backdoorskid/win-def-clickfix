rule Trojan_Win32_SuspAD_B_2147955588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspAD.B"
        threat_id = "2147955588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WMIObject Win32_NTDomain" ascii //weight: 1
        $x_1_3 = "findstr DomainController" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspWMI_A_2147955593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWMI.A"
        threat_id = "2147955593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWMI"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "if((Get-WmiObject -class Win32_ComputerSystem).PartOfDomain)" ascii //weight: 1
        $x_1_3 = "((Get-WmiObject -class Win32_ComputerSystem).Domain)" ascii //weight: 1
        $x_1_4 = "gwmi win32_group -Filter" ascii //weight: 1
        $x_1_5 = "Domain=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

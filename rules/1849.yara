rule Trojan_Win32_SuspWmiPs_B_2147955600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmiPs.B"
        threat_id = "2147955600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject" ascii //weight: 1
        $x_1_3 = "Win32_NetworkAdapterConfiguration" ascii //weight: 1
        $x_1_4 = "-Filter IPEnabled=TRUE -ComputerName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SusWmiPs_B_2147954147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWmiPs.B"
        threat_id = "2147954147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject" ascii //weight: 1
        $x_1_3 = "Win32_NetworkAdapterConfiguration" ascii //weight: 1
        $x_1_4 = "-Filter IPEnabled=TRUE -ComputerName" ascii //weight: 1
        $n_1_5 = "69802c98-2ci2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

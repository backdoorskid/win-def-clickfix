rule Trojan_Win32_SusWmiPs_C_2147954148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWmiPs.C"
        threat_id = "2147954148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject" ascii //weight: 1
        $x_1_3 = "win32_physicalmemory" ascii //weight: 1
        $n_1_4 = "69802c98-2cj2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

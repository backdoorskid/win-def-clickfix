rule Trojan_Win32_SuspWmiPs_C_2147955601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmiPs.C"
        threat_id = "2147955601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWmiPs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject" ascii //weight: 1
        $x_1_3 = "win32_physicalmemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

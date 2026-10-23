rule Trojan_Win32_SuspWmiPs_A_2147955599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWmiPs.A"
        threat_id = "2147955599"
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
        $x_1_3 = "-ClassName" ascii //weight: 1
        $x_1_4 = "Win32_OperatingSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

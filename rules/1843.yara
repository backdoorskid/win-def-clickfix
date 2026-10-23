rule Trojan_Win32_SuspWMI_MK_2147955597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWMI.MK"
        threat_id = "2147955597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWMI"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-WmiObject win32_Processor" ascii //weight: 1
        $x_1_3 = "Select NumberOfCores" ascii //weight: 1
        $x_1_4 = "cmd.exe /c" ascii //weight: 1
        $x_1_5 = "timeout" ascii //weight: 1
        $x_1_6 = "/T" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

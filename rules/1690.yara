rule Trojan_Win32_SuspProxi_D_2147955581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxi.D"
        threat_id = "2147955581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp\\lb" ascii //weight: 1
        $x_1_3 = "Start-Process -FilePath" ascii //weight: 1
        $x_1_4 = "Windows\\System32\\unregmp2.exe" ascii //weight: 1
        $x_1_5 = "-ArgumentList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

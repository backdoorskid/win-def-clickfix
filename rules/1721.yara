rule Trojan_Win32_SuspProxy_M_2147955570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.M"
        threat_id = "2147955570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c Unblock-File" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "Invoke-DefenderDownload.ps1" ascii //weight: 1
        $x_1_4 = "defender_test.txt:ADS.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

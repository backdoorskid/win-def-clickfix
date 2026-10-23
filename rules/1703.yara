rule Trojan_Win32_SuspProxy_D_2147954129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.D"
        threat_id = "2147954129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
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
        $n_1_6 = "69802c98-2ce2-4a17-98n0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

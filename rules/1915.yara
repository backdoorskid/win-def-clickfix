rule Trojan_Win32_SusWMI_C_2147954143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusWMI.C"
        threat_id = "2147954143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusWMI"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic.exe os get" ascii //weight: 1
        $x_1_2 = "lastbootuptime" ascii //weight: 1
        $x_1_3 = "powershell.exe /wInd" ascii //weight: 1
        $x_1_4 = "Get-WmiObject -Class Win32_ComputerSystem" ascii //weight: 1
        $x_1_5 = "powershell.exe -wind hidden" ascii //weight: 1
        $x_1_6 = "cmd.exe /c" ascii //weight: 1
        $x_1_7 = "AppData\\Local\\Temp\\startup_vrun.bat" ascii //weight: 1
        $x_1_8 = "powershell.exe -c" ascii //weight: 1
        $x_1_9 = "Start-Process -WindowStyle hidden -FilePath" ascii //weight: 1
        $n_1_10 = "69802c98-2cc2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

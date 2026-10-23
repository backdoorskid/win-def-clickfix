rule Trojan_Win32_SuspWMI_D_2147955596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWMI.D"
        threat_id = "2147955596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWMI"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic.exe" ascii //weight: 1
        $x_1_2 = "Win32_videocontroller" ascii //weight: 1
        $x_1_3 = "adapterram" ascii //weight: 1
        $x_1_4 = "powershell.exe" ascii //weight: 1
        $x_1_5 = "Get-Random -Minimum" ascii //weight: 1
        $x_1_6 = "powershell.exe -c" ascii //weight: 1
        $x_1_7 = "Get-WmiObject win32_ComputerSystem" ascii //weight: 1
        $x_1_8 = "Select TotalPhysicalMemory" ascii //weight: 1
        $x_1_9 = "Get-WmiObject" ascii //weight: 1
        $x_1_10 = "win32_bios" ascii //weight: 1
        $x_1_11 = "Start-Sleep" ascii //weight: 1
        $x_1_12 = "-s" wide //weight: 1
        $x_1_13 = "Unblock-File" ascii //weight: 1
        $x_1_14 = "AppData\\Local\\Temp\\idle_time.ps1" ascii //weight: 1
        $x_1_15 = "ComputerSystem" ascii //weight: 1
        $x_1_16 = "TotalPhysicalMemory" ascii //weight: 1
        $x_1_17 = "OS get" ascii //weight: 1
        $x_1_18 = "FreePhysicalMemory" ascii //weight: 1
        $x_1_19 = "TotalVirtualMemorySize" ascii //weight: 1
        $x_1_20 = "FreeVirtualMemory" ascii //weight: 1
        $x_1_21 = "Win32_Battery" ascii //weight: 1
        $x_1_22 = "BatteryStatus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

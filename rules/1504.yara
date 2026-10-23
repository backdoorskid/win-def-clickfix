rule Trojan_Win32_SuspAD_E_2147955591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspAD.E"
        threat_id = "2147955591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspAD"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "arp -a" ascii //weight: 1
        $x_1_2 = "ipconfig.exe /all" ascii //weight: 1
        $x_1_3 = "getmac.exe" ascii //weight: 1
        $x_1_4 = "route PRINT" ascii //weight: 1
        $x_1_5 = "netstat -nao" ascii //weight: 1
        $x_1_6 = "net.exe localgroup" ascii //weight: 1
        $x_1_7 = "whoami.exe /all" ascii //weight: 1
        $x_1_8 = "netsh.exe advfirewall firewall show rule name=all" ascii //weight: 1
        $x_1_9 = "tasklist.exe /svc" ascii //weight: 1
        $x_1_10 = "powershell.exe -enc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_PFApp_SqlSrvExploit_A_2147961922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PFApp_SqlSrvExploit.A"
        threat_id = "2147961922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PFApp_SqlSrvExploit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "111"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "wmicimv2/win32_process" wide //weight: 100
        $x_100_2 = "process call create" wide //weight: 100
        $x_100_3 = "start-process" wide //weight: 100
        $x_10_4 = "Invoke-WebRequest" wide //weight: 10
        $x_10_5 = "iwr " wide //weight: 10
        $x_10_6 = "DownloadFile(" wide //weight: 10
        $x_10_7 = "DownloadString(" wide //weight: 10
        $x_10_8 = "FromBase64String" wide //weight: 10
        $x_1_9 = "powershell.exe" wide //weight: 1
        $x_1_10 = "pwsh.exe" wide //weight: 1
        $x_1_11 = "cmd.exe" wide //weight: 1
        $x_1_12 = "powershell_ise.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            ((2 of ($x_100_*))) or
            (all of ($x*))
        )
}

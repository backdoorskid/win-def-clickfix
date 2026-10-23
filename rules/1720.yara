rule Trojan_Win32_SuspProxy_L_2147955569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.L"
        threat_id = "2147955569"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Get-ExecutionPolicy" ascii //weight: 1
        $x_1_3 = "-scope CurrentUser -Force" ascii //weight: 1
        $x_1_4 = "Set-ExecutionPolicy" ascii //weight: 1
        $x_1_5 = "Unrestricted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

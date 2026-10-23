rule Trojan_Win32_SusProxy_L_2147954117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.L"
        threat_id = "2147954117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
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
        $n_1_6 = "69802c98-2ce2-4a17-98a0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_Ofisus_B_2147731692_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.gen!B"
        threat_id = "2147731692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "powershell" wide //weight: 5
        $x_5_2 = ".DownloadFile(" wide //weight: 5
        $x_5_3 = "'http://" wide //weight: 5
        $x_5_4 = ".exe'" wide //weight: 5
        $x_1_5 = " -w 1 " wide //weight: 1
        $x_1_6 = " -WindowStyle Hidden " wide //weight: 1
        $x_1_7 = "Start-Process " wide //weight: 1
        $x_1_8 = ".ShellExecute(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

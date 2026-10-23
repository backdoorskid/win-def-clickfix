rule Trojan_PowerShell_WannaMine_A_2147725599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/WannaMine.A"
        threat_id = "2147725599"
        type = "Trojan"
        platform = "PowerShell: "
        family = "WannaMine"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/info6.ps1')}else{IEX(New-Object Net.WebClient).DownloadString('" wide //weight: 1
        $x_1_2 = "\\y1.bat && SCHTASKS /create /RU System /SC DAILY /TN yastcat " wide //weight: 1
        $x_1_3 = "'SCM Event Filter')))) {IEX(New-Object Net.WebClient).DownloadString" wide //weight: 1
        $x_1_4 = "JABzAHQAaQBtAGUAPQBbAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABdADoAOgBUAGkAYwBrAEMAbwB1AG4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

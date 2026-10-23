rule Trojan_PowerShell_SuspLoadExec_ZA_2147972905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/SuspLoadExec.ZA!MTB"
        threat_id = "2147972905"
        type = "Trojan"
        platform = "PowerShell: "
        family = "SuspLoadExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[guid]::NewGuid().ToString() + '.msi" wide //weight: 1
        $x_1_2 = ".DownloadFile($" wide //weight: 1
        $x_1_3 = ".WebClient" wide //weight: 1
        $x_1_4 = "System.Windows.Forms.MessageBox]::Show(" wide //weight: 1
        $x_1_5 = "$tmp$" wide //weight: 1
        $x_1_6 = "/qn" wide //weight: 1
        $x_1_7 = "/norestart" wide //weight: 1
        $x_1_8 = "[IO.Path]::Combine(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

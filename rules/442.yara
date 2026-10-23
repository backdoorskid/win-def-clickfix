rule TrojanDownloader_Script_CosmicPulse_BB_2147953150_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Script/CosmicPulse.BB!dha"
        threat_id = "2147953150"
        type = "TrojanDownloader"
        platform = "Script: "
        family = "CosmicPulse"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "UserInitMprLogonScript" wide //weight: 10
        $x_10_2 = "reg add" wide //weight: 10
        $x_1_3 = "-WindowStyle Hidden" wide //weight: 1
        $x_1_4 = "New-Object System.Net.WebClient" wide //weight: 1
        $x_1_5 = "Invoke-Command" wide //weight: 1
        $x_1_6 = "[scriptblock]::Create" wide //weight: 1
        $x_1_7 = "DownloadString" wide //weight: 1
        $x_1_8 = "powershell" wide //weight: 1
        $x_1_9 = "-ep bypass" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

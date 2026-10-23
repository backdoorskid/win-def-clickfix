rule Trojan_PowerShell_Powersploit_G_2147725325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Powersploit.G"
        threat_id = "2147725325"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Powersploit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/powershellmafia/powersploit/" wide //weight: 1
        $x_1_2 = "/peewpw/invoke-wcmdump/" wide //weight: 1
        $x_1_3 = "/mattifestation/powersploit/" wide //weight: 1
        $x_1_4 = "/powershellempire/" wide //weight: 1
        $x_1_5 = "/PowerPick/PSInjector/" wide //weight: 1
        $x_1_6 = "/master/PowerUp/PowerUp." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

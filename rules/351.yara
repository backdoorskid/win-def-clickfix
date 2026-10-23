rule Trojan_PowerShell_DownInfo_B_2147933995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/DownInfo.B"
        threat_id = "2147933995"
        type = "Trojan"
        platform = "PowerShell: "
        family = "DownInfo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "chromeuseragentupdater" wide //weight: 10
        $x_10_2 = "microsoftversionagent" wide //weight: 10
        $x_10_3 = "windowssoftwareupdater" wide //weight: 10
        $x_10_4 = "versionupdaterlegacy" wide //weight: 10
        $x_10_5 = "systemhealthcheckerlegacy" wide //weight: 10
        $x_10_6 = "get-registryvalue \"hklm:\\software\\microsoft\\cryptography\" \"machineguid\"" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

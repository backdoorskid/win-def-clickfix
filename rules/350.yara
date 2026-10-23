rule Trojan_PowerShell_DownInfo_A_2147933994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/DownInfo.A"
        threat_id = "2147933994"
        type = "Trojan"
        platform = "PowerShell: "
        family = "DownInfo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "invoke-webrequest -uri \"$api/script?machineid=$guid\"" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

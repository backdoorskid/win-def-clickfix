rule Trojan_PowerShell_DownInfo_BA_2147943278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/DownInfo.BA"
        threat_id = "2147943278"
        type = "Trojan"
        platform = "PowerShell: "
        family = "DownInfo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "get-registryvalue \"hklm:\\software\\microsoft\\cryptography\" \"machineguid\"" wide //weight: 10
        $x_10_2 = "if (-not ($response.headers[\"content-type\"].startswith(\"text/html\") -and $content.startswith(\"#\"))) { throw }" wide //weight: 10
        $x_10_3 = "$apis = @($apis | select-object -skip 1) + $api" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

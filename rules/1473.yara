rule Trojan_Win32_SusMachete_B_2147955535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusMachete.B"
        threat_id = "2147955535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusMachete"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c cd " ascii //weight: 1
        $x_1_2 = "geoip.exe" ascii //weight: 1
        $x_1_3 = " && " wide //weight: 1
        $x_1_4 = "\\AppData\\Roaming\\Chrome\\Google" ascii //weight: 1
        $x_1_5 = "> geoip.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

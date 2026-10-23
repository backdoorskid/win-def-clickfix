rule Trojan_Win32_RundllLolBin_AK_2147796581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AK"
        threat_id = "2147796581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "-command" wide //weight: 1
        $x_1_3 = "invoke-expression" wide //weight: 1
        $x_1_4 = "iex" wide //weight: 1
        $x_1_5 = ".invoke" wide //weight: 1
        $x_1_6 = "FromBase64String" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

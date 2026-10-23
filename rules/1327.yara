rule Trojan_Win32_RundllLolBin_AJ_2147795803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RundllLolBin.AJ"
        threat_id = "2147795803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RundllLolBin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_1_2 = "-command" wide //weight: 1
        $x_1_3 = "invoke-expression" wide //weight: 1
        $x_1_4 = "iex" wide //weight: 1
        $x_1_5 = ".invoke" wide //weight: 1
        $n_1_6 = "sentinelCommand" wide //weight: -1
        $n_1_7 = "customscripthandler" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (4 of ($x*))
}

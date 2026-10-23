rule Trojan_Win32_Amynex_A_2147777774_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amynex.A"
        threat_id = "2147777774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amynex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "[Net.Dns]::GetHostAddresses(" wide //weight: 1
        $x_1_3 = ")[0].IPAddressToString+'" wide //weight: 1
        $x_1_4 = "='http://'+$" wide //weight: 1
        $x_1_5 = "DownloadData" wide //weight: 1
        $x_1_6 = "]::Create().ComputeHash(" wide //weight: 1
        $x_1_7 = "|foreach{" wide //weight: 1
        $x_1_8 = "{IEX(-join[char[]]$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

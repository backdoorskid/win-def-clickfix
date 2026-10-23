rule Trojan_Win32_Powessere_N_2147770116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.N"
        threat_id = "2147770116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\powershell.exe" wide //weight: 1
        $x_1_2 = "get-itemproperty -path 'HK" wide //weight: 1
        $x_1_3 = "[Byte]::Parse($" wide //weight: 1
        $x_1_4 = "]::HexNumber" wide //weight: 1
        $x_1_5 = "]::GetDomain().Load($" wide //weight: 1
        $x_1_6 = ".EntryPoint.invoke($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

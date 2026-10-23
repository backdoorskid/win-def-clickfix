rule Ransom_Win32_BastaLoader_A_2147841936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BastaLoader.A"
        threat_id = "2147841936"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BastaLoader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\rundll32.exe" wide //weight: 1
        $x_1_2 = "_c.dll,visibleentry" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ofisus_A_2147731060_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.A"
        threat_id = "2147731060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cmd.exe" wide //weight: 1
        $x_1_2 = "cMd.EXE /c poWerShelL.exe -ec KABOAGUAdwAtAE8A" wide //weight: 1
        $x_1_3 = "cmd.exe /c powershell.exe -NoP -EC JABpAG4AcwB0AGEA" wide //weight: 1
        $x_1_4 = "cMd.eXe /c p^o^w^e^r^s^h^E^L^L^.^e^x^e^ ^-^e^c^ ^K^A^B^O^" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Powemet_F_2147741515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.F"
        threat_id = "2147741515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\WMIC.exe" wide //weight: 1
        $x_1_2 = "'PRocEss'" wide //weight: 1
        $x_1_3 = " CrEate " wide //weight: 1
        $x_1_4 = "CoNveRT]::FROMBaSe64STRInG(" wide //weight: 1
        $x_1_5 = "$shEllID[1]+$shelliD[13]+'x')" wide //weight: 1
        $x_1_6 = ".READtoeNd(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

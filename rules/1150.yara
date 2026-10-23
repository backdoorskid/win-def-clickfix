rule Trojan_Win32_Powemet_A_2147725438_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.A!attk"
        threat_id = "2147725438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "regsvr32" wide //weight: 5
        $x_5_2 = "/s" wide //weight: 5
        $x_5_3 = "/u" wide //weight: 5
        $x_1_4 = "/i:http" wide //weight: 1
        $x_1_5 = "/i:\\\\" wide //weight: 1
        $x_5_6 = "scrobj.dll" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

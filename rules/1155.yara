rule Trojan_Win32_Powemet_B_2147757077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.B!attk"
        threat_id = "2147757077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "regsvr32" wide //weight: 5
        $x_1_2 = "/i:url:http" wide //weight: 1
        $x_1_3 = "-i:url:http" wide //weight: 1
        $x_10_4 = " scrobj.dll" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

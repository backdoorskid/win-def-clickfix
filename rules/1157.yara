rule Trojan_Win32_Powemet_L_2147789148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powemet.L!attk"
        threat_id = "2147789148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powemet"
        severity = "Critical"
        info = "attk: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "regsvr32" wide //weight: 10
        $x_10_2 = "scrobj.dll" wide //weight: 10
        $x_10_3 = ".sct" wide //weight: 10
        $x_1_4 = " /i:" wide //weight: 1
        $x_1_5 = " -i:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

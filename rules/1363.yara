rule Trojan_Win32_ShortPipe_A_2147897225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ShortPipe.A!dha"
        threat_id = "2147897225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ShortPipe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wscript.exe" wide //weight: 1
        $x_1_2 = "trash.dat" wide //weight: 1
        $x_1_3 = "trash.dll" wide //weight: 1
        $x_1_4 = "//e:vbScript" wide //weight: 1
        $x_1_5 = "//b" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

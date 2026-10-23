rule Trojan_Win32_Neoreblamy_HA_2147943523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Neoreblamy.HA!MTB"
        threat_id = "2147943523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Neoreblamy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "forfiles" wide //weight: 1
        $x_5_2 = "wscript.exe /c cmd /C @FNAME" wide //weight: 5
        $x_5_3 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 63 00 6d 00 64 00 20 00 2f 00 43 00 20 00 [0-104] 2e 00 77 00 73 00 66 00 5e 00 20 00 40 00 46 00 4e 00 41 00 4d 00 45 00}  //weight: 5, accuracy: Low
        $x_10_4 = {70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 [0-56] 2e 00 77 00 73 00 66 00 5e 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

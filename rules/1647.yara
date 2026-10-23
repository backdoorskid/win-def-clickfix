rule Trojan_Win32_SuspLolbinLaunch_A_2147768658_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLolbinLaunch.A!schtasks"
        threat_id = "2147768658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLolbinLaunch"
        severity = "Critical"
        info = "schtasks: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_1_2 = " /Create " wide //weight: 1
        $x_1_3 = " /SC ONSTART " wide //weight: 1
        $x_1_4 = {20 00 2f 00 52 00 55 00 20 00 [0-4] 4e 00 54 00 20 00 41 00 55 00 54 00 48 00 4f 00 52 00 49 00 54 00 59 00 5c 00 53 00 59 00 53 00 54 00 45 00 4d 00}  //weight: 1, accuracy: Low
        $x_1_5 = {20 00 2f 00 54 00 4e 00 20 00 29 20 20 00 20 00}  //weight: 1, accuracy: Low
        $x_1_6 = {20 00 2f 00 54 00 52 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 [0-8] 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_7 = {20 00 2f 00 54 00 52 00 20 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 [0-8] 5c 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

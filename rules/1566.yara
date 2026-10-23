rule Trojan_Win32_SuspClickFix_Z3_2147971223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Z3"
        threat_id = "2147971223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = " --headless " wide //weight: 2
        $x_2_2 = "=rundll32" wide //weight: 2
        $x_1_3 = "=pushd" wide //weight: 1
        $x_1_4 = {21 00 20 00 5c 00 5c 00 [0-96] 2e 00 [0-21] 5c 00}  //weight: 1, accuracy: Low
        $x_1_5 = {21 00 20 00 5c 00 5c 00 [0-96] 2e 00 [0-21] 40 00 [0-8] 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

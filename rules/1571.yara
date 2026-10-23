rule Trojan_Win32_SuspClickFix_Z5_2147971420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Z5"
        threat_id = "2147971420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "cmd /v:on /" wide //weight: 5
        $x_1_2 = {26 00 73 00 65 00 74 00 20 00 2f 08 08 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = "=mshta" wide //weight: 1
        $x_1_4 = "=where" wide //weight: 1
        $x_1_5 = "=pushd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

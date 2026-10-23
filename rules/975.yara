rule Trojan_Win32_MpTamperBlockNewFirewall_AE_2147773091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockNewFirewall.AE"
        threat_id = "2147773091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MpTamperBlockNewFirewall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\system32\\windowspowershell\\v1.0\\powershell.exe" wide //weight: 2
        $x_2_2 = "new-netfirewallrule " wide //weight: 2
        $x_2_3 = {2d 00 73 00 65 00 72 00 [0-15] 77 00 69 00 6e 00 64 00 65 00 66 00 65 00 6e 00 64 00}  //weight: 2, accuracy: Low
        $x_1_4 = {2d 00 61 00 63 00 [0-15] 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 61 00 63 00 [0-15] 30 00}  //weight: 1, accuracy: Low
        $x_1_6 = "86ea4d9c-2d5a-4818-880b-08e4f5ae7aee" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

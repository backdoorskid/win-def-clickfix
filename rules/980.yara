rule Trojan_Win32_MpTamperBlockNewFirewall_EE_2147773095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MpTamperBlockNewFirewall.EE"
        threat_id = "2147773095"
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
        $x_2_3 = {2d 00 70 00 72 00 6f 00 67 00 [0-160] 6d 00 73 00 6d 00 70 00 65 00 6e 00 67 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_1_4 = {2d 00 61 00 63 00 [0-15] 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2d 00 61 00 63 00 [0-15] 30 00}  //weight: 1, accuracy: Low
        $x_1_6 = "326423b7-3fe4-4ed2-8dd2-34e1543dc89a" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ofisus_B_2147731692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ofisus.gen!B"
        threat_id = "2147731692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ofisus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\cmd.exe" wide //weight: 1
        $x_1_2 = "POwErsHell" wide //weight: 1
        $x_1_3 = " -W" wide //weight: 1
        $x_1_4 = "{1}" wide //weight: 1
        $x_1_5 = "-f" wide //weight: 1
        $x_1_6 = ").Invoke(" wide //weight: 1
        $x_1_7 = ".GETFIE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

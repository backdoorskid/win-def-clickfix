rule Trojan_Win32_Socgolsh_SH_2147934464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Socgolsh.SH"
        threat_id = "2147934464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Socgolsh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {63 00 6d 00 64 00 00 05 3e 00 3e 00 [0-255] 5c 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 74 00 65 00 6d 00 70 00}  //weight: 10, accuracy: Low
        $x_1_2 = "whoami" wide //weight: 1
        $x_1_3 = "ping" wide //weight: 1
        $x_1_4 = "nltest" wide //weight: 1
        $x_1_5 = "net use" wide //weight: 1
        $x_1_6 = "findstr" wide //weight: 1
        $x_1_7 = "powershell" wide //weight: 1
        $x_1_8 = "ls $env:appdata\\microsoft\\signatures" wide //weight: 1
        $n_100_9 = "maxuserports1.log" wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

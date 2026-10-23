rule Trojan_Win32_Powessere_L_2147735903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powessere.L"
        threat_id = "2147735903"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powessere"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $n_10_1 = "mshta.exe" wide //weight: -10
        $x_1_2 = "\\cmd.exe" wide //weight: 1
        $x_1_3 = " /c start " wide //weight: 1
        $x_1_4 = "\\AppData\\Local\\" wide //weight: 1
        $x_1_5 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-32] 3d 00 [0-32] 3b 00}  //weight: 1, accuracy: Low
        $x_1_6 = "=new ActiveXObject(WScript.Shell);" wide //weight: 1
        $x_1_7 = {2e 00 52 00 65 00 67 00 52 00 65 00 61 00 64 00 28 00 48 00 4b 00 43 00 55 00 5c 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 5c 00 [0-32] 5c 00 5c 00 [0-32] 29 00 3b 00}  //weight: 1, accuracy: Low
        $x_1_8 = {3b 00 65 00 76 00 61 00 6c 00 28 00 [0-32] 29 00 3b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

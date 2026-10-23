rule Trojan_Win32_Amadey_PPA_2147954622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.PPA!MTB"
        threat_id = "2147954622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_1_2 = "hidden" wide //weight: 1
        $x_1_3 = "WScript.Shell" wide //weight: 1
        $x_1_4 = "Start-Sleep" wide //weight: 1
        $x_2_5 = {53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 [0-16] 2e 00 6c 00 6e 00 6b 00}  //weight: 2, accuracy: Low
        $x_2_6 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_1_7 = "Save" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

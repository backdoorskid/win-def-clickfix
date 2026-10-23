rule Trojan_Win32_Amadey_Y_2147932740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.Y!MTB"
        threat_id = "2147932740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[system.reflection.assembly]::(" wide //weight: 1
        $x_1_2 = ".substring(" wide //weight: 1
        $x_1_3 = "[system.iO.file]::(" wide //weight: 1
        $x_1_4 = "system.iO.memorystream" wide //weight: 1
        $x_1_5 = "-join" wide //weight: 1
        $x_1_6 = "[convert]::(" wide //weight: 1
        $x_1_7 = ".invoke($" wide //weight: 1
        $x_1_8 = ".createdecryptor(" wide //weight: 1
        $x_1_9 = ".split([environment]::" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

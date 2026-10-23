rule Trojan_Win32_Qakbot_DB_2147782539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qakbot.DB"
        threat_id = "2147782539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "iroto.tio" wide //weight: 10
        $x_10_2 = "lertio.cersw" wide //weight: 10
        $x_1_3 = "regsvr32.exe -s" wide //weight: 1
        $x_1_4 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 [0-4] 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 72 00 75 00}  //weight: 1, accuracy: Low
        $x_1_5 = "nt authority\\system" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

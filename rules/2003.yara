rule TrojanDownloader_Win32_Astaroth_YY_2147919970_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Astaroth.YY"
        threat_id = "2147919970"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Astaroth"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "112"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "\\ProgramData\\" wide //weight: 1
        $x_10_3 = "curl -A" wide //weight: 10
        $x_100_4 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-255] 2f 00 3f 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 00 2d 00 6f 00 20 00}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

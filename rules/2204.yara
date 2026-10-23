rule TrojanDownloader_Win64_ClickFix_WebDAV_2147977449_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/ClickFix.WebDAV"
        threat_id = "2147977449"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "ClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = "start" wide //weight: 1
        $x_1_3 = "/v:on" wide //weight: 1
        $x_1_4 = "pushd&set" wide //weight: 1
        $x_1_5 = "rundll32&call" wide //weight: 1
        $x_1_6 = "@SSL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Adposhel_I_2147730216_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Adposhel.I"
        threat_id = "2147730216"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Adposhel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo bitsadmin /complete" ascii //weight: 1
        $x_1_2 = "echo bitsadmin /cancel" ascii //weight: 1
        $x_2_3 = "echo start /b /min regsvr32.exe /s /n /i:" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

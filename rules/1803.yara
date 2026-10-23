rule Trojan_Win32_SuspSettings_G_2147954153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSettings.G"
        threat_id = "2147954153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSettings"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Unblock-File" ascii //weight: 1
        $x_1_3 = "AppData\\Local\\Temp\\enum_disk.ps1" ascii //weight: 1
        $n_1_4 = "69802c98-2cn2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

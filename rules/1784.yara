rule Trojan_Win32_SusProxy_N_2147954119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.N"
        threat_id = "2147954119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "GfxDownloadWrapper.exe" ascii //weight: 1
        $x_1_4 = "GfxDownloadWrapper.dll" ascii //weight: 1
        $x_1_5 = "AppData\\Local\\Intel\\Games\\settings.dll" ascii //weight: 1
        $x_1_6 = "tasklist /svc | findstr /i" ascii //weight: 1
        $n_1_7 = "69802c98-2ce2-4a17-98c0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

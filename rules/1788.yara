rule Trojan_Win32_SusProxy_R_2147954123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusProxy.R"
        threat_id = "2147954123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rundll32.exe" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "comDll.dll" ascii //weight: 1
        $x_1_4 = "startWorker" ascii //weight: 1
        $n_1_5 = "69802c98-2ce2-4a17-98g0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

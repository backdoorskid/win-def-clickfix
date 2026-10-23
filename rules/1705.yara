rule Trojan_Win32_SuspProxy_E_2147954130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.E"
        threat_id = "2147954130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c" ascii //weight: 1
        $x_1_2 = "AppData\\Local\\Temp" ascii //weight: 1
        $x_1_3 = "ormat %SYSTEMDRIVE%" ascii //weight: 1
        $x_1_4 = "/fs:NPRunner" ascii //weight: 1
        $n_1_5 = "69802c98-2ce2-4a17-98o0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

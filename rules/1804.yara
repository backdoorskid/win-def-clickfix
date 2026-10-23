rule Trojan_Win32_SuspSettings_H_2147954154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSettings.H"
        threat_id = "2147954154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSettings"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "New-Object" ascii //weight: 1
        $x_1_3 = "System.Threading.Mutex(" ascii //weight: 1
        $x_1_4 = "Dispose()" ascii //weight: 1
        $n_1_5 = "69802c98-2cm2-4a17-98w0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspProxy_A_2147954126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspProxy.A"
        threat_id = "2147954126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspProxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "set-location -path" ascii //weight: 1
        $x_1_3 = "windows\\diagnostics\\system\\networking" ascii //weight: 1
        $x_1_4 = "import-module" ascii //weight: 1
        $x_1_5 = "UtilityFunctions.ps1" ascii //weight: 1
        $x_1_6 = "[Program]::Main()" ascii //weight: 1
        $n_1_7 = "69802c98-2ce2-4a17-98k0-3a9220ad0157" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

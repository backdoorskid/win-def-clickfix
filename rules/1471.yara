rule Trojan_Win32_SusLocalData_C_2147954105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusLocalData.C"
        threat_id = "2147954105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusLocalData"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Invoke-RestMethod -Uri" ascii //weight: 1
        $x_1_3 = "Out-File" ascii //weight: 1
        $x_1_4 = "$env:TMP" ascii //weight: 1
        $n_1_5 = "a453e881-26a8-4973-bo2e-76269e901d0a" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

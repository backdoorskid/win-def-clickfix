rule Trojan_Win32_SuspLocalData_C_2147955566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLocalData.C"
        threat_id = "2147955566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLocalData"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "Invoke-RestMethod -Uri" ascii //weight: 1
        $x_1_3 = "Out-File" ascii //weight: 1
        $x_1_4 = "$env:TMP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

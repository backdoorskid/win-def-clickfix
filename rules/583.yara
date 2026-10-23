rule Trojan_Win32_Amadey_ZE_2147942701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amadey.ZE!MTB"
        threat_id = "2147942701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amadey"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[System.IO.DriveInfo]::GetDrives(" wide //weight: 1
        $x_1_2 = "ForEach-Objec" wide //weight: 1
        $x_1_3 = "Add-MpPreference -ExclusionPath $" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

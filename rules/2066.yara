rule VirTool_Win32_Magniber_B_2147846013_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Magniber.B"
        threat_id = "2147846013"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = "=Set-MpPreference -EnableControlledFolderAccess 0 && cmd /c echo %" wide //weight: 1
        $x_1_3 = "=(Get-WmiObject Win32_ShadowCopy).Delete() && cmd /c echo %" wide //weight: 1
        $x_1_4 = "% | powershell -" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

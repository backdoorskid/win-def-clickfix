rule Trojan_Win32_Tofsee_BSA_2147941452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tofsee.BSA!MTB"
        threat_id = "2147941452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tofsee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "150"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "[AppDomain]::CurrentDomain.GetAssemblies" wide //weight: 10
        $x_10_3 = "Where-Object{$_." wide //weight: 10
        $x_10_4 = "[Reflection.Assembly]::Load(" wide //weight: 10
        $x_10_5 = "LocalMachine.OpenSubkey(" wide //weight: 10
        $x_10_6 = ".EntryPoint.Invoke($" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

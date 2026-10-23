rule Trojan_Win32_FileFix_B_2147945920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.B!MTB"
        threat_id = "2147945920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "while($" wide //weight: 1
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = ".docx" wide //weight: 1
        $x_1_4 = "[System.Windows.MessageBox]::Show(($" wide //weight: 1
        $x_1_5 = "Get-Random" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

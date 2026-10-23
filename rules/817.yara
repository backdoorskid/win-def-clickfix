rule Trojan_Win32_FileFix_A_2147945919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.A!MTB"
        threat_id = "2147945919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[System.Windows.Forms.MessageBox]::Show($" wide //weight: 1
        $x_1_2 = "Start-Process" wide //weight: 1
        $x_1_3 = "http" wide //weight: 1
        $x_1_4 = "System.Windows.Forms.SendKeys]::SendWait" wide //weight: 1
        $x_1_5 = "for($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspWMI_B_2147955594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspWMI.B"
        threat_id = "2147955594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspWMI"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe -c" ascii //weight: 1
        $x_1_2 = "[Security.Principal.WindowsIdentity]::GetCurrent()" ascii //weight: 1
        $x_1_3 = "(New-Object Security.Principal.WindowsPrincipal" ascii //weight: 1
        $x_1_4 = "IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

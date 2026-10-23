rule VirTool_Win32_SuspRemoteCmdCommand_J_2147922310_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspRemoteCmdCommand.J"
        threat_id = "2147922310"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRemoteCmdCommand"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "/Q /c" wide //weight: 1
        $x_1_3 = "1> C:\\windows\\temp" wide //weight: 1
        $x_1_4 = "2>&1 && certutil -encodehex -f" wide //weight: 1
        $x_1_5 = "do reg add HKLM\\" wide //weight: 1
        $x_1_6 = "&& del" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

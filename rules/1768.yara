rule Trojan_Win32_SuspRootInstall_A_2147939803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspRootInstall.A"
        threat_id = "2147939803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspRootInstall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& certutil.exe" ascii //weight: 1
        $x_1_2 = "-addstore root" ascii //weight: 1
        $x_1_3 = "\\windows\\temp\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

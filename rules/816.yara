rule Trojan_Win32_FileFix_DC_2147945906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FileFix.DC!MTB"
        threat_id = "2147945906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FileFix"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "112"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_10_2 = "; # --- Security identity" wide //weight: 10
        $x_10_3 = "; # Verify you are human" wide //weight: 10
        $x_10_4 = "; # ----- Identity" wide //weight: 10
        $x_10_5 = "$fab;" wide //weight: 10
        $x_1_6 = "Invoke-Expression $" wide //weight: 1
        $x_1_7 = "= Invoke-WebRequest" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

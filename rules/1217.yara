rule Trojan_Win32_PsExec_DK_2147972893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsExec.DK!MTB"
        threat_id = "2147972893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-command $" wide //weight: 1
        $x_1_2 = "= [system.Text.encoding]" wide //weight: 1
        $x_1_3 = "::Frombase64String( $" wide //weight: 1
        $x_1_4 = ".replace('" wide //weight: 1
        $x_1_5 = "','A') ) );powershell.exe -w" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

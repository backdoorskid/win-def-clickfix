rule Trojan_Win32_SusPsExec_FO_2147975333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusPsExec.FO!MTB"
        threat_id = "2147975333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusPsExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-W Hidden -EP Bypass" wide //weight: 1
        $x_1_3 = "-NoP -C" wide //weight: 1
        $x_1_4 = "[Net.SecurityProtocolType]::Tls12" wide //weight: 1
        $x_1_5 = ".DownloadString" wide //weight: 1
        $x_1_6 = "http" wide //weight: 1
        $x_1_7 = "[scriptblock]" wide //weight: 1
        $x_1_8 = "::Create((New-Object Net.WebClient)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

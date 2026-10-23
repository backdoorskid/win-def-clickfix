rule Trojan_Win32_SchExec_HK_2147948697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SchExec.HK!MTB"
        threat_id = "2147948697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SchExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "certutil -addstore -f root " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

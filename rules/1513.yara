rule Trojan_Win32_Suspbxor_BC_2147980375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Suspbxor.BC!MTB"
        threat_id = "2147980375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Suspbxor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "::FromBase64String" wide //weight: 1
        $x_1_2 = ".GetBytes($" wide //weight: 1
        $x_1_3 = "[byte[]]::new($" wide //weight: 1
        $x_1_4 = "-bxor ($" wide //weight: 1
        $x_1_5 = "[System.IO.File]::WriteAllText" wide //weight: 1
        $x_1_6 = "[Guid]::NewGuid().ToString(" wide //weight: 1
        $x_1_7 = "[System.IO.File]::OpenRead" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

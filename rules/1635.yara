rule Trojan_Win32_SuspLoad_BF_2147980389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspLoad.BF!MTB"
        threat_id = "2147980389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[sysTEm.io.FILE]::reADAlLByTEs" wide //weight: 1
        $x_1_2 = "] -BXOR $" wide //weight: 1
        $x_1_3 = "::iNterACt()" wide //weight: 1
        $x_1_4 = "[sysTEM.REfLEctIon.asSembly]::LoaD($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

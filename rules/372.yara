rule Trojan_PowerShell_MpTamperPShell_HF_2147904653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/MpTamperPShell.HF"
        threat_id = "2147904653"
        type = "Trojan"
        platform = "PowerShell: "
        family = "MpTamperPShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$scheduleservice = new-object -comobject schedule.service).connect();" wide //weight: 1
        $x_1_2 = "$scheduleservice.getfolder('\\').gettask($taskname).runex($null, 0, 0, $trustedinstallername)" wide //weight: 1
        $x_1_3 = "out-file $batchfile -encoding ascii; $taskname = 'privacy.sexy invoke';" wide //weight: 1
        $x_1_4 = "register-scheduledtask -taskname $taskname -action $taskaction -settings $settings -force -erroraction stop" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

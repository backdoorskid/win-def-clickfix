rule TrojanDownloader_JS_NeutrinoEK_G_2147725837_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:JS/NeutrinoEK.gen!G"
        threat_id = "2147725837"
        type = "TrojanDownloader"
        platform = "JS: JavaScript scripts"
        family = "NeutrinoEK"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".tmp && start wscript //B //E:JScript " wide //weight: 1
        $x_1_2 = "\" \"Mozilla/5.0 (Windows NT 6.1; " wide //weight: 1
        $x_1_3 = "=\"PE\\x00\\x00\"" wide //weight: 1
        $x_1_4 = "=0;256" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

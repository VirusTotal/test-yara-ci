rule test
{
    meta:
        hash = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
    strings:
        $x1 = "POST /cdn-cgi/" ascii
        $x2 = "/dev/misc/watchdog" fullword ascii
        $x3 = "/dev/watchdog" ascii
        $x5 = ".mdebug.abi32" fullword ascii
        $s1 = "LCOGQGPTGP" fullword ascii
        $s2 = "QUKLEKLUKVJOG" fullword ascii
        $s3 = "CFOKLKQVPCVMP" fullword ascii
        $s4 = "QWRGPTKQMP" fullword ascii
        $s5 = "HWCLVGAJ" fullword ascii
        $s6 = "NKQVGLKLE" fullword ascii
    condition:
        uint16(0) == 0x457f and filesize < 200KB and
        (
            ( 1 of ($x*) and 1 of ($s*) ) or 4 of ($s*)
        )
}

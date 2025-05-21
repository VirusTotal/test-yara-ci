rule test
{
    meta:
        hash = "05c78c3052b390435e53a87e3d31e9fb17f7c76bb4df2814313bca24735ce81c"
    strings:
        $x1 = "POST /cdn-cgi/" ascii
        $x2 = "/dev/misc/watchdog" fullword ascii
        $x3 = "/dev/watchdog" ascii
        $x5 = ".mdebug.abi32" fullword ascii
    condition:
        uint16(0) == 0x457f and filesize < 200KB and all of them
}

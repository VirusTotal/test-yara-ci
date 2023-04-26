rule test
{
    meta:
        hash = "b05aced06b1f787002fe1d1771a2e12463bab3d58e63daf3c364141784afaacc"
        hash = "c05aced06b1f787002fe1d1771a2e12463bab3d58e63daf3c364141784afaacc"
        hash = "9562da870dcd42966a0ef53d820ccc3c1829f5df35a63aae6bf4ac038173ce51"
        hash = "f02d9fbc0ee0e697ba023ca8f584b5d1b63d4694354684222a1410ff475122fc"
        hash = "d0da52523e6dd22b7dd8c4c25fa42536917b965a07730df70f6a2ff563b82540"
        hash = "a3eb43648d6fd0e2b60910ee916aa7dc079ed68a1c5607b643e84cdccfa651a9"
        hash = "e5c02f9a4455ed5b20ceb94590f6376c80c9cac7466710d6b006a2da99271234"
        hash = "20fc3fd8e8db26409fa0bfebfd795c9f786d7eefbc5a5c374a98f27baa2dbf3b"
        hash = "5abc5d590560be8054558fd6628b77107efbf69b7377db76801f082bbef6dde8"
        hash = "b7d710d62f2a7981e101889c8135b55f6468f1cb16110e1959e5aaf2344efc60"
        hash = "eff3ac3fbe347c98c224a14c9b17ad7274e376a70862b8e8762b746120f50699"
        hash = "c31db73aa2ca0c1ab1f03efb56db2f7fb3d635e7035f57b34fa7aa7e0f45fd2a"
        hash = "e8cccc9f9b124826c0e43897f0e21124b4b0cd7991f434b0dd7838bed7e361b3"
    strings:
        $embarcadero = "This program must be run under Win32" ascii
    condition:
        all of them
}

rule HATCHERY_SandboxEvasion_Sleep {
    meta:
        description = "Detects Sleep/SleepEx with long delays — common sandbox evasion (sleep bomb)"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "high"
        mitre_attck = "T1497: Virtualization/Sandbox Evasion"

    strings:
        $s1 = "Sleep" ascii wide
        $s2 = "SleepEx" ascii wide
        $s3 = "WaitForSingleObject" ascii wide
        $s4 = "NtDelayExecution" ascii wide

    condition:
        any of them
}

rule HATCHERY_SandboxEvasion_DesktopCheck {
    meta:
        description = "Detects checks for desktop environment artifacts — sandbox evasion"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "medium"
        mitre_attck = "T1497.001: System Checks"

    strings:
        $s1 = "GetSystemMetrics" ascii wide
        $s2 = "SM_CXSCREEN" ascii wide
        $s3 = "SM_CYSCREEN" ascii wide
        $s4 = "SM_MOUSEPRESENT" ascii wide
        $s5 = "GetCursorPos" ascii wide
        $s6 = "GetDoubleClickTime" ascii wide
        $s7 = "EnumWindows" ascii wide
        $s8 = "FindWindowA" ascii wide
        $s9 = "FindWindowW" ascii wide

    condition:
        2 of them
}

rule HATCHERY_SandboxEvasion_VM_Artifacts {
    meta:
        description = "Detects virtual machine / sandbox artifact checks"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "high"
        mitre_attck = "T1497.001: System Checks"

    strings:
        $s1 = "VMWARE" ascii nocase wide
        $s2 = "VBOX" ascii nocase wide
        $s3 = "QEMU" ascii nocase wide
        $s4 = "XEN" ascii nocase wide
        $s5 = "sandbox" ascii nocase wide
        $s6 = "malware" ascii nocase wide
        $s7 = "sample" ascii nocase wide
        $s8 = "virus" ascii nocase wide
        $s9 = "cuckoo" ascii nocase wide
        $s10 = "CAPE" ascii nocase wide
        $s11 = "joebox" ascii nocase wide
        $s12 = "\\\\.\\VBoxMiniRdrDN" ascii wide
        $s13 = "\\\\.\\pipe\\cuckoo" ascii wide
        $s14 = "HKLM\\SOFTWARE\\VMware" ascii wide
        $s15 = "HKLM\\SOFTWARE\\Oracle" ascii wide
        $s16 = "HKLM\\SOFTWARE\\Wine" ascii wide

    condition:
        2 of them
}

rule HATCHERY_SandboxEvasion_ProcessCheck {
    meta:
        description = "Detects enumeration of running processes — sandbox/analyst detection"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "medium"
        mitre_attck = "T1497.001: System Checks"

    strings:
        $s1 = "CreateToolhelp32Snapshot" ascii wide
        $s2 = "Process32First" ascii wide
        $s3 = "Process32Next" ascii wide
        $s4 = "EnumProcesses" ascii wide
        $s5 = "NtQuerySystemInformation" ascii wide
        $s6 = "wireshark" ascii nocase
        $s7 = "procmon" ascii nocase
        $s8 = "procexp" ascii nocase
        $s9 = "x64dbg" ascii nocase
        $s10 = "ollydbg" ascii nocase
        $s11 = "idaq" ascii nocase
        $s12 = "pestudio" ascii nocase

    condition:
        any of ($s1, $s2, $s3, $s4, $s5) or any of ($s6, $s7, $s8, $s9, $s10, $s11, $s12)
}

rule HATCHERY_SandboxEvasion_DriverCheck {
    meta:
        description = "Detects checks for analysis tool drivers — sandbox evasion"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "high"
        mitre_attck = "T1497.001: System Checks"

    strings:
        $s1 = "\\\\.\\NTICE" ascii wide
        $s2 = "\\\\.\\SICE" ascii wide
        $s3 = "\\\\.\\SIWVID" ascii wide
        $s4 = "\\\\.\\TRW" ascii wide
        $s5 = "\\\\.\\REGSYS" ascii wide
        $s6 = "\\\\.\\FILEM" ascii wide
        $s7 = "\\\\.\\EXT2" ascii wide
        $s8 = "\\\\.\\PICE" ascii wide

    condition:
        any of them
}
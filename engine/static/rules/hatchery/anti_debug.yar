rule HATCHERY_AntiDebug_IsDebuggerPresent {
    meta:
        description = "Detects IsDebuggerPresent API call — common anti-debug technique"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "high"
        mitre_attck = "T1622: Debugger Evasion"
        reference = "https://attack.mitre.org/techniques/T1622/"

    strings:
        $s1 = "IsDebuggerPresent" ascii wide
        $s2 = "kernel32.IsDebuggerPresent" ascii wide
        $s3 = "CheckRemoteDebuggerPresent" ascii wide
        $s4 = "NtQueryInformationProcess" ascii wide

    condition:
        any of them
}

rule HATCHERY_AntiDebug_TimingCheck {
    meta:
        description = "Detects timing-based anti-debug checks (GetTickCount, QueryPerformanceCounter)"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "medium"
        mitre_attck = "T1622: Debugger Evasion"

    strings:
        $s1 = "GetTickCount" ascii wide
        $s2 = "QueryPerformanceCounter" ascii wide
        $s3 = "QueryPerformanceFrequency" ascii wide
        $s4 = "timeGetTime" ascii wide
        $s5 = "rdtsc" ascii

    condition:
        2 of them
}

rule HATCHERY_AntiDebug_OutputDebugString {
    meta:
        description = "Detects OutputDebugString anti-debug technique"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "medium"
        mitre_attck = "T1622: Debugger Evasion"

    strings:
        $s1 = "OutputDebugStringA" ascii wide
        $s2 = "OutputDebugStringW" ascii wide
        $s3 = "SetLastError" ascii wide

    condition:
        any of ($s1, $s2, $s3)
}

rule HATCHERY_AntiDebug_PEB_Check {
    meta:
        description = "Detects direct PEB debugging flag checks — advanced anti-debug"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "high"
        mitre_attck = "T1622: Debugger Evasion"

    strings:
        $s1 = { 64 A1 00 00 00 00 }  // mov eax, fs:[0] — PEB access
        $s2 = { 64 8B 0D 00 00 00 00 } // mov ecx, fs:[0]
        $s3 = "BeingDebugged" ascii wide
        $s4 = "NtGlobalFlag" ascii wide
        $s5 = "ProcessHeap" ascii wide

    condition:
        any of them
}
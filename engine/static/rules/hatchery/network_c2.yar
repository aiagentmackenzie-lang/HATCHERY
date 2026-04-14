rule HATCHERY_Network_HTTP_C2 {
    meta:
        description = "Detects potential HTTP-based C2 communication patterns"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "high"
        mitre_attck = "T1071.001: Web Protocols"

    strings:
        $s1 = "InternetOpenA" ascii wide
        $s2 = "InternetOpenW" ascii wide
        $s3 = "InternetConnectA" ascii wide
        $s4 = "InternetConnectW" ascii wide
        $s5 = "HttpOpenRequestA" ascii wide
        $s6 = "HttpOpenRequestW" ascii wide
        $s7 = "HttpSendRequestA" ascii wide
        $s8 = "HttpSendRequestW" ascii wide
        $s9 = "WinHttpOpen" ascii wide
        $s10 = "WinHttpConnect" ascii wide
        $s11 = "WinHttpSendRequest" ascii wide
        $s12 = "URLDownloadToFileA" ascii wide
        $s13 = "URLDownloadToFileW" ascii wide

    condition:
        2 of them
}

rule HATCHERY_Network_Socket_C2 {
    meta:
        description = "Detects raw socket-based C2 communication"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "high"
        mitre_attck = "T1071: Application Layer Protocol"

    strings:
        $s1 = "WSAStartup" ascii wide
        $s2 = "socket" ascii wide
        $s3 = "connect" ascii wide
        $s4 = "send" ascii wide
        $s5 = "recv" ascii wide
        $s6 = "WSACleanup" ascii wide
        $s7 = "closesocket" ascii wide

    condition:
        3 of them
}

rule HATCHERY_Network_DNS_Query {
    meta:
        description = "Detects DNS query functions — potential DGA or DNS tunneling"
        author = "HATCHERY"
        date = "2026-04-14"
        severity = "medium"
        mitre_attck = "T1071.004: DNS"

    strings:
        $s1 = "gethostbyname" ascii wide
        $s2 = "getaddrinfo" ascii wide
        $s3 = "GetAddrInfoW" ascii wide
        $s4 = "DnsQuery_A" ascii wide
        $s5 = "DnsQuery_W" ascii wide
        $s6 = "DnsQuery_UTF8" ascii wide

    condition:
        any of them
}
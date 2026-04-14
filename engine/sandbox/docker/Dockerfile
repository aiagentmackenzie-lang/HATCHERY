# HATCHERY sandbox container — isolated detonation environment
# Ubuntu 22.04 with syscall tracing, network capture, and fake desktop indicators
#
# Trade-off documented: Docker containers share the host kernel.
# VM-level isolation (Cuckoo/CAPE) is stronger for evasive malware,
# but Docker is faster, simpler, and sufficient for demonstrating
# sandbox concepts. See SPEC.md for detailed trade-off analysis.

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install analysis tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    strace \
    tcpdump \
    inotify-tools \
    python3 \
    python3-pip \
    curl \
    wget \
    netcat-openbsd \
    dnsutils \
    procps \
    psmisc \
    lsof \
    file \
    xxd \
    && rm -rf /var/lib/apt/lists/*

# Anti-evasion: Make it look like a real desktop
# Malware commonly checks hostname, username, uptime, and running processes
# to detect sandbox environments. We set realistic values.
RUN echo "DESKTOP-WIN10" > /etc/hostname && \
    useradd -m -s /bin/bash user && \
    echo "user:Password123" | chpasswd && \
    mkdir -p /home/user/Desktop /home/user/Documents /home/user/Downloads \
             /home/user/Pictures /home/user/Music /home/user/Videos && \
    ln -sf /bin/true /usr/bin/vmtoolsd && \
    ln -sf /bin/true /usr/bin/VBoxService && \
    ln -sf /bin/true /usr/bin/qemu-ga

# Create fake browser and application indicators
RUN mkdir -p /home/user/.mozilla/firefox /home/user/.config/google-chrome && \
    echo "[Profile0]" > /home/user/.mozilla/firefox/profiles.ini && \
    echo "Name=default" >> /home/user/.mozilla/firefox/profiles.ini && \
    echo "IsRelative=1" >> /home/user/.mozilla/firefox/profiles.ini && \
    echo "Path=profiles/default" >> /home/user/.mozilla/firefox/profiles.ini && \
    mkdir -p /home/user/.mozilla/firefox/profiles/default

# Create HATCHERY directories
RUN mkdir -p /hatchery/sample /hatchery/output/strace /hatchery/output/tcpdump \
             /hatchery/output/inotify /hatchery/output/dropped /hatchery/output/filesystem

# Copy entrypoint
COPY entrypoint.sh /hatchery/entrypoint.sh
RUN chmod +x /hatchery/entrypoint.sh

# Set working directory
WORKDIR /hatchery

# Run as the fake user by default (more realistic for malware)
USER user

# Default: run sample with strace attached
ENTRYPOINT ["/hatchery/entrypoint.sh"]
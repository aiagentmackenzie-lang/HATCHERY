# HATCHERY sandbox guest — isolated detonation environment
#
# Design notes (read before editing):
#
#  * This is a LINUX guest. The previous revision faked Windows artifacts
#    (DESKTOP-WIN10 hostname, C:\ environment variables, vmtoolsd/VBoxService
#    stubs) inside a Linux kernel. That is worse than faking nothing: a sample
#    that checks CPUID sees a hypervisor vendor string and a Linux kernel while
#    its environment claims to be Windows. Inconsistency is itself a signal.
#    A Linux guest gets a consistent Linux workstation profile instead.
#
#  * Privileged monitoring, unprivileged execution. The entrypoint runs as root
#    so tcpdump can open a raw socket (NET_RAW is in Docker's default cap set)
#    and so strace can attach, then drops to the unprivileged `user` account to
#    actually execute the sample. The sample never runs as root.
#
#  * Do not try to hide the host from the sample here. At isolation tier 1 the
#    sample can read the host kernel version, CPU count, RAM and uptime through
#    /proc regardless of what this image does. That is a limitation of the tier,
#    not of the image. See engine/sandbox/isolation.py.

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV LANG=en_US.UTF-8
ENV TERM=xterm-256color

# Analysis tooling + a plausible workstation software footprint in one layer.
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    file \
    git \
    inotify-tools \
    iproute2 \
    less \
    lsof \
    netcat-openbsd \
    psmisc \
    procps \
    python3 \
    strace \
    tcpdump \
    unzip \
    util-linux \
    vim-tiny \
    wget \
    xxd \
    && rm -rf /var/lib/apt/lists/*

# Consistent Linux workstation profile.
# The account, hostname and home directory contents are internally consistent:
# a Linux user, a Linux shell history, a Linux browser profile. Nothing here
# claims to be Windows, and nothing here claims to be a hypervisor guest.
RUN useradd -m -u 1000 -s /bin/bash user \
    && echo "user:hatchery" | chpasswd \
    && mkdir -p /home/user/Desktop /home/user/Documents /home/user/Downloads \
                /home/user/Pictures /home/user/.config \
                /home/user/.mozilla/firefox \
    && printf '# files downloaded here\n' > /home/user/Documents/notes.txt \
    && printf 'ls -la\ncat todo.txt\n' > /home/user/.bash_history \
    && printf '[Profile0]\nName=default\nIsRelative=1\nPath=profiles/default\n' \
        > /home/user/.mozilla/firefox/profiles.ini \
    && chown -R user:user /home/user

# HATCHERY working directories. Owned by the unprivileged user because the
# sample and the tracers both write here and the container's filesystem (not a
# host bind mount) is now the hand-off point.
RUN mkdir -p /hatchery/sample /hatchery/output/strace /hatchery/output/tcpdump \
             /hatchery/output/inotify /hatchery/output/dropped \
             /hatchery/output/filesystem /hatchery/output/exec \
    && chown -R user:user /hatchery

COPY entrypoint.sh /hatchery/entrypoint.sh
RUN chmod +x /hatchery/entrypoint.sh

WORKDIR /hatchery

# Root at container start: required so the tracers can attach and capture.
# entrypoint.sh drops to `user` before executing the sample.
ENTRYPOINT ["/hatchery/entrypoint.sh"]

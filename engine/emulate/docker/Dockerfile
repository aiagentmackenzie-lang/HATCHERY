# HATCHERY emulation image — runs Mandiant Speakeasy on a Windows PE.
#
# This is a SEPARATE image from the detonation guest (engine/sandbox/docker).
# Emulation is not isolation: Speakeasy interprets x86/x64 in Unicorn and
# emulates the Windows API in Python, so the sample never executes natively.
# The residual attack surface is the *host parser/emulator* handling hostile
# bytes (pefile, Speakeasy's loader, capstone, Unicorn), which is why it runs in
# a container with --network none, a non-root user, dropped capabilities and
# resource caps — not as a library call on the analyst's desktop (D21).
#
# The pinned emulator is a pre-release: speakeasy-emulator==2.0.0b6 (MIT).
# capa and YARA-X are included so snapshot analysis can run inside the image;
# in this revision HATCHERY runs it host-side over recovered snapshot bytes.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN pip install --no-cache-dir \
        "speakeasy-emulator==2.0.0b6" \
        "flare-capa==9.4.0" \
        "yara-x>=1.16"

# Unprivileged emulation account. The sample and the report are exchanged
# through /hatchery, never a host bind mount (D5).
RUN useradd -m -u 1000 -s /usr/sbin/nologin hatchery \
    && mkdir -p /hatchery/sample /hatchery/output \
    && chown -R hatchery:hatchery /hatchery

COPY entrypoint.sh /hatchery/entrypoint.sh
RUN chmod 0755 /hatchery/entrypoint.sh

WORKDIR /hatchery
USER hatchery

ENTRYPOINT ["/hatchery/entrypoint.sh"]

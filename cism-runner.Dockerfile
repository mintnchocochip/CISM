FROM python:3.12-slim

# D5 (AUDIT.md): pinned to the exact candidate versions on this base image
# as of 2026-09-23 (`apt-cache policy`), so a build next month can't
# silently pull a different tool version. A version bump is a deliberate
# edit here, not something that just happens on rebuild.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap=7.95+dfsg-3 \
    curl=8.14.1-2+deb13u5 \
    whatweb=0.5.5-1 \
    dnsenum=1.3.2-1 \
    hydra=9.5-3 \
    bubblewrap=0.12.0-1~deb13u1 \
    git=1:2.47.3-0+deb13u1 \
    perl=5.40.1-6+deb13u1 \
    libnet-ssleay-perl=1.94-3 \
    && rm -rf /var/lib/apt/lists/*

# nikto is in Debian's non-free component (not enabled by default) — install
# from upstream instead of patching sources.list for one package. Pinned to
# the 2.6.1 tag's dereferenced commit (D5, AUDIT.md) — not bare HEAD, and
# the checkout is verified against that exact SHA so a force-moved tag
# fails the build loudly instead of silently shipping different code.
RUN git clone --branch 2.6.1 --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    cd /opt/nikto && \
    [ "$(git rev-parse HEAD)" = "d201dac320fc5187eac75e723dd07a716196ec5a" ] && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

RUN install -d /usr/share/wordlists && \
    printf 'wronguser\nadmin\nmsfadmin\n' > /usr/share/wordlists/common-users.txt && \
    printf 'wrongpass\ntoor\nmsfadmin\n' > /usr/share/wordlists/common-passwords.txt

WORKDIR /cism
COPY pyproject.toml .
COPY cism ./cism
COPY run_agent.py .

RUN pip install --no-cache-dir -e ".[agent]"

# Non-root at runtime (D1 in AUDIT.md): everything above needs root (apt,
# the nikto clone, pip install); nothing after this line does. bwrap's own
# --unshare-user path still works unprivileged — see docker/README.md for
# the matching docker run flags (cap-drop, seccomp profile, no-new-privileges)
# this depends on.
RUN useradd --create-home --uid 1000 cism && chown -R cism:cism /cism
USER cism

ENTRYPOINT ["python", "run_agent.py"]

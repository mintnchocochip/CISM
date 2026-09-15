FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl whatweb dnsenum hydra bubblewrap \
    git perl libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

# nikto is in Debian's non-free component (not enabled by default) — install
# from upstream instead of patching sources.list for one package.
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto

RUN install -d /usr/share/wordlists && \
    printf 'wronguser\nadmin\nmsfadmin\n' > /usr/share/wordlists/common-users.txt && \
    printf 'wrongpass\ntoor\nmsfadmin\n' > /usr/share/wordlists/common-passwords.txt

WORKDIR /cism
COPY pyproject.toml .
COPY cism ./cism
COPY run_agent.py .

RUN pip install --no-cache-dir -e ".[agent]"

ENTRYPOINT ["python", "run_agent.py"]

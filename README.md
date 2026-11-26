# cascalho-agent

Lets the Cascalho web page use the A3 smartcard on this machine. It listens
on `http://127.0.0.1:1917`, and for every signature it shows a native dialog
where the user picks a certificate and types the PIN. Signing, the RFB's
mutual TLS and the PKCS#11 work happen in [`libnfse`](https://github.com/drimotta/nfse);
this program is the HTTP layer and the dialogs.

## Build

Needs a C compiler, cJSON, GTK 4 on Linux (Cocoa on macOS), and an `nfse`
checkout built with `cargo build --lib`.

```bash
# Debian/Ubuntu: sudo apt install libcjson-dev libgtk-4-dev pkg-config
# macOS:         brew install cjson pkg-config
make agent NFSE_DIR=../../nfse
./build/cascalho-agent --origin https://cascalho.example
```

Options: `--origin` (repeatable; only these pages are served), `--module`
(the PKCS#11 module; OpenSC's by default), `--port` (1917), `--pairing-store`.
`--sefin-url`, `--adn-url`, `--ca-bundle` and `--recovery-delays-ms` override
the RFB connection, for tests.

## Protocol

Every request must come from an allowed `Origin` with `Host: 127.0.0.1:1917`
(or `localhost:1917`), which also stops DNS rebinding. Preflights are
answered, including Chrome's private network access header.

| Method and path | Pairing | Body | Response |
| --- | --- | --- | --- |
| `GET /v1/status` | no | | `{"version", "nfse", "paired"}` |
| `POST /v1/pair` | no | `{}` | `{"token"}` after the user allows the site |
| `GET /v1/certificates` | yes | | `{"certificates": [{"token", "id", "subject", "not_after", "der_b64"}]}` |
| `POST /v1/login` | yes | `{"challenge_b64"}` | `{"signature_b64", "certificate_b64", "algorithm", "prefix"}` |
| `POST /v1/issue` | yes | `{"environment", "unsigned_xml"}` | `{"dps_id", "signed_xml", "chave_acesso", "nfse_xml", "pdf_b64"}` |

Paired requests send `Authorization: Bearer <token>`. The token is kept per
origin in a file only the user can read.

The login signature covers `prefix` followed by the challenge bytes
(RSA PKCS#1 v1.5, SHA-256). The issue dialog shows the DPS number, the
customer and the amount read from the DPS itself, never text from the page.

Errors are `{"error": {"code", "message"}}` with these statuses:

| Status | `code` | Meaning |
| --- | --- | --- |
| 400 | `input` | Bad request, or a DPS this library did not build |
| 401 | `unpaired` | Pair first |
| 403 | `forbidden`, `pin`, `pin_locked` | Wrong origin or host, wrong or blocked PIN |
| 409 | `cancelled` | The user said no |
| 422 | `rejected` | The RFB rejected the DPS; `messages` lists why |
| 502 | `token`, `network` | No card, no module, or the RFB is unreachable |
| 504 | `unknown_outcome` | Look the DPS up before sending anything again |

On 422 and 504 the response also carries `dps_id` and `signed_xml`, so the
server can keep the signed DPS and never reuse its number.

## Tests

```bash
make test NFSE_DIR=../../nfse
```

`make unit` runs the C unit tests under AddressSanitizer and UBSan.
`make integration` starts the agent with scripted dialogs (`src/ui_fake.c`)
against a SoftHSM token and a local mTLS server standing in for the RFB;
it needs `softhsm2`, OpenSC's `pkcs11-tool`, `openssl` and Python 3.

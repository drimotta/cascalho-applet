"""The agent end to end: a real socket, a SoftHSM token standing in for the
card, scripted dialogs, and a local mTLS server standing in for the RFB.

Needs softhsm2-util, pkcs11-tool and openssl. Run with `make integration`.
"""

import base64
import ctypes
import gzip
import http.client
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
AGENT = os.environ.get("AGENT_BIN", os.path.join(ROOT, "build", "cascalho-agent-test"))
NFSE_DIR = os.environ.get("NFSE_DIR", os.path.join(ROOT, "..", "..", "nfse"))
NFSE_LIB = os.environ.get("NFSE_LIB", os.path.join(NFSE_DIR, "target", "debug"))
ORIGIN = "https://cascalho.example"
PIN = "1234"


def softhsm_module():
    for p in [os.environ.get("SOFTHSM_MODULE", ""),
              "/usr/lib/softhsm/libsofthsm2.so",
              "/opt/homebrew/lib/softhsm/libsofthsm2.so",
              "/usr/local/lib/softhsm/libsofthsm2.so"]:
        if p and os.path.exists(p):
            return p
    return None


def run(cwd, *args):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True,
                   env=dict(os.environ, SOFTHSM2_CONF=os.path.join(cwd, "softhsm2.conf")))


def make_token(d):
    """A test CA, a client certificate whose key is on a SoftHSM token, and
    a server certificate for localhost."""
    os.makedirs(os.path.join(d, "tokens"))
    with open(os.path.join(d, "softhsm2.conf"), "w") as f:
        f.write(f"directories.tokendir = {d}/tokens\n")
    run(d, "softhsm2-util", "--init-token", "--free", "--label", "A3-TEST",
        "--pin", PIN, "--so-pin", "5678")
    with open(os.path.join(d, "client.ext"), "w") as f:
        f.write("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,"
                "nonRepudiation,keyEncipherment\nextendedKeyUsage=clientAuth\n")
    with open(os.path.join(d, "server.ext"), "w") as f:
        f.write("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,"
                "keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n")
    run(d, "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key",
        "-subj", "/CN=Test CA", "-days", "2", "-out", "ca.pem",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for name, cn in [("client", "/C=BR/CN=EMPRESA TESTE:12345678000195"), ("server", "/CN=localhost")]:
        run(d, "openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key",
            "-subj", cn, "-out", f"{name}.csr")
        run(d, "openssl", "x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey",
            "ca.key", "-CAcreateserial", "-days", "2", "-extfile", f"{name}.ext",
            "-out", f"{name}.pem")
    run(d, "openssl", "pkey", "-in", "client.key", "-outform", "DER", "-out", "client.key.der")
    run(d, "openssl", "x509", "-in", "client.pem", "-outform", "DER", "-out", "client.der")
    run(d, "openssl", "x509", "-in", "client.pem", "-pubkey", "-noout", "-out", "client.pub")
    for file, kind in [("client.key.der", "privkey"), ("client.der", "cert")]:
        run(d, "pkcs11-tool", "--module", softhsm_module(), "--login", "--pin", PIN,
            "--write-object", file, "--type", kind, "--id", "01", "--label", "signing")


def unsigned_dps():
    """An unsigned DPS built by libnfse, as the server would build it."""
    lib = ctypes.CDLL(os.path.join(NFSE_LIB, "libnfse.dylib" if os.uname().sysname == "Darwin"
                                   else "libnfse.so"))
    lib.nfse_build_dps.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.nfse_free.argtypes = [ctypes.c_void_p]
    with open(os.path.join(NFSE_DIR, "tests", "fixtures", "nfse-ibscbs.xml")) as f:
        reuse = f.read()
    req = json.dumps({"environment": "staging", "serie": "1", "n_dps": "42",
                      "reuse_xml": reuse}).encode()
    out = ctypes.c_void_p()
    code = lib.nfse_build_dps(req, ctypes.byref(out))
    resp = json.loads(ctypes.string_at(out).decode())
    lib.nfse_free(out)
    assert code == 0, resp
    return resp["xml"]


class Rfb(http.server.BaseHTTPRequestHandler):
    """Sefin and ADN: issues K1, or rejects when told to."""
    reject = False
    seen = []

    def log_message(self, *args):
        pass

    def _send(self, status, ctype, body):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        cert = self.connection.getpeercert()
        Rfb.seen.append(("POST", self.path, cert is not None, body))
        if Rfb.reject:
            self._send(400, "application/json",
                       b'{"erros":[{"codigo":"E0004","descricao":"Id"}]}')
            return
        nfse = base64.b64encode(gzip.compress(b"<NFSe>K1</NFSe>")).decode()
        self._send(201, "application/json",
                   json.dumps({"chaveAcesso": "K1", "nfseXmlGZipB64": nfse}).encode())

    def do_GET(self):
        Rfb.seen.append(("GET", self.path, True, b""))
        if self.path == "/danfse/K1":
            self._send(200, "application/pdf", b"%PDF-1.4 test")
        else:
            self._send(404, "text/plain", b"")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(softhsm_module() and shutil.which("pkcs11-tool") and shutil.which("openssl"),
                     "SoftHSM, pkcs11-tool or openssl missing")
class AgentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        make_token(cls.dir)
        os.environ["SOFTHSM2_CONF"] = os.path.join(cls.dir, "softhsm2.conf")

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(cls.dir, "server.pem"), os.path.join(cls.dir, "server.key"))
        ctx.load_verify_locations(os.path.join(cls.dir, "ca.pem"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        cls.rfb = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Rfb)
        cls.rfb.socket = ctx.wrap_socket(cls.rfb.socket, server_side=True)
        threading.Thread(target=cls.rfb.serve_forever, daemon=True).start()
        base = f"https://localhost:{cls.rfb.server_address[1]}"

        cls.port = free_port()
        cls.log = os.path.join(cls.dir, "dialogs.log")
        cls.agent = subprocess.Popen(
            [AGENT, "--origin", ORIGIN, "--port", str(cls.port), "--module", softhsm_module(),
             "--pairing-store", os.path.join(cls.dir, "pairings"),
             "--sefin-url", f"{base}/SefinNacional", "--adn-url", base,
             "--ca-bundle", os.path.join(cls.dir, "ca.pem"), "--recovery-delays-ms", "[10]"],
            env=dict(os.environ, CASCALHO_FAKE_UI_LOG=cls.log, CASCALHO_FAKE_UI_FILE=cls.ui_file()),
            stderr=subprocess.PIPE)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.1).close()
                break
            except OSError:
                time.sleep(0.05)
        cls.ui("confirm=yes")
        status, body = cls.call("POST", "/v1/pair", {})
        assert status == 200, body
        cls.token = body["token"]

    @classmethod
    def tearDownClass(cls):
        cls.agent.terminate()
        cls.agent.wait()
        cls.rfb.shutdown()
        shutil.rmtree(cls.dir, ignore_errors=True)

    @classmethod
    def ui_file(cls):
        return os.path.join(cls.dir, "ui")

    @classmethod
    def ui(cls, spec):
        with open(cls.ui_file(), "w") as f:
            f.write(spec)

    @classmethod
    def call(cls, method, path, body=None, token=None):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=30)
        headers = {"Origin": ORIGIN, "Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        conn.request(method, path, json.dumps(body) if body is not None else None, headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, json.loads(data) if data else None

    def setUp(self):
        Rfb.seen.clear()
        Rfb.reject = False
        if os.path.exists(self.log):
            os.remove(self.log)

    def dialogs(self):
        with open(self.log) as f:
            return [line.rstrip("\n").split("\t") for line in f]

    def test_status_reports_the_pairing(self):
        status, body = self.call("GET", "/v1/status", token=self.token)
        self.assertEqual(status, 200)
        self.assertTrue(body["paired"])

    def test_lists_the_usable_certificates(self):
        status, body = self.call("GET", "/v1/certificates", token=self.token)
        self.assertEqual(status, 200, body)
        [cert] = body["certificates"]
        self.assertEqual(cert["token"], "A3-TEST")
        self.assertEqual(cert["id"], "01")
        self.assertIn("EMPRESA TESTE:12345678000195", cert["subject"])

    def test_login_signs_the_challenge_with_the_chosen_key(self):
        self.ui(f"pick=0;pin={PIN}")
        challenge = os.urandom(32)
        status, body = self.call("POST", "/v1/login",
                                 {"challenge_b64": base64.b64encode(challenge).decode()},
                                 token=self.token)
        self.assertEqual(status, 200, body)
        signed = body["prefix"].encode() + challenge
        with open(os.path.join(self.dir, "c.bin"), "wb") as f:
            f.write(signed)
        with open(os.path.join(self.dir, "c.sig"), "wb") as f:
            f.write(base64.b64decode(body["signature_b64"]))
        run(self.dir, "openssl", "dgst", "-sha256", "-verify", "client.pub",
            "-signature", "c.sig", "c.bin")
        [(kind, title, detail)] = self.dialogs()
        self.assertEqual((kind, title), ("pick", "Sign in"))
        self.assertIn(ORIGIN, detail)

    def test_a_wrong_pin_is_reported(self):
        self.ui("pick=0;pin=0000")
        status, body = self.call("POST", "/v1/login",
                                 {"challenge_b64": base64.b64encode(b"x" * 32).decode()},
                                 token=self.token)
        self.assertEqual(status, 403, body)
        self.assertEqual(body["error"]["code"], "pin")

    def test_cancelling_the_dialog(self):
        self.ui("cancel")
        status, body = self.call("POST", "/v1/login",
                                 {"challenge_b64": base64.b64encode(b"x" * 32).decode()},
                                 token=self.token)
        self.assertEqual(status, 409, body)
        self.assertEqual(body["error"]["code"], "cancelled")

    def test_issue_signs_submits_and_fetches_the_pdf(self):
        self.ui(f"pick=0;pin={PIN}")
        status, body = self.call("POST", "/v1/issue",
                                 {"environment": "staging", "unsigned_xml": unsigned_dps()},
                                 token=self.token)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["chave_acesso"], "K1")
        self.assertEqual(body["nfse_xml"], "<NFSe>K1</NFSe>")
        self.assertEqual(base64.b64decode(body["pdf_b64"]), b"%PDF-1.4 test")
        self.assertTrue(body["dps_id"].startswith("DPS"))
        self.assertIn("<Signature", body["signed_xml"])
        post = [s for s in Rfb.seen if s[0] == "POST"]
        self.assertEqual(len(post), 1)
        self.assertTrue(post[0][2], "client certificate presented")
        [(kind, title, detail)] = self.dialogs()
        self.assertEqual(title, "Issue NFS-e")
        for words in ["Example Corp", "5500.00", "DPS 42", "staging"]:
            self.assertIn(words, detail)

    def test_a_rejection_returns_the_messages_and_the_signed_dps(self):
        Rfb.reject = True
        self.ui(f"pick=0;pin={PIN}")
        status, body = self.call("POST", "/v1/issue",
                                 {"environment": "staging", "unsigned_xml": unsigned_dps()},
                                 token=self.token)
        self.assertEqual(status, 422, body)
        self.assertEqual(body["error"]["code"], "rejected")
        self.assertEqual(body["messages"], ["E0004 - Id"])
        self.assertIn("<Signature", body["signed_xml"])

    def test_a_tampered_dps_is_not_signed(self):
        self.ui(f"pick=0;pin={PIN}")
        xml = unsigned_dps().replace("5500.00", "1.00")
        status, body = self.call("POST", "/v1/issue",
                                 {"environment": "staging", "unsigned_xml": xml.replace("</infDPS>", "<x></x></infDPS>")},
                                 token=self.token)
        self.assertEqual(status, 400, body)
        self.assertEqual(Rfb.seen, [])


if __name__ == "__main__":
    unittest.main()

import json

import quoxproof
from quoxproof.cli import main


def _make_session(tmp_path, session="cli-sess"):
    quoxproof.configure(store_root=str(tmp_path), session_id=session)

    @quoxproof.tool
    def echo(x):
        return x

    echo("a")
    echo("b")
    return quoxproof.capture._active().store.session_path(session)


def test_verify_ok_exit_zero(tmp_path, capsys):
    path = _make_session(tmp_path)
    rc = main(["verify", str(path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "status: INTACT" in out


def test_verify_tampered_exit_one(tmp_path, capsys):
    path = _make_session(tmp_path)
    lines = path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["output_hash"] = "f" * 64
    lines[0] = json.dumps(rec, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    rc = main(["verify", str(path)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "status: BROKEN" in out


def test_show_lists_receipts(tmp_path, capsys):
    path = _make_session(tmp_path)
    rc = main(["show", str(path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "echo" in out


def test_keygen(tmp_path, capsys):
    rc = main(["keygen", "--out-dir", str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "key_id:" in out
    assert (tmp_path / "keys" / "quoxproof_ed25519.pub").exists()

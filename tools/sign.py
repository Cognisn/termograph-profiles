#!/usr/bin/env python3
"""Sign every bundle under ``bundles/`` and regenerate ``index.json``.

Run by ``.github/workflows/publish.yml`` once a pull request adding a
``bundles/*.tgprofile`` file is merged to ``main`` and ``TERMOGRAPH_SIGNING_KEY``
is configured as a repository secret. Do not run this by hand against the
real key outside CI — see the workflow's own comment on why the key must
never be typed, echoed, or committed.

What it does, matching Termograph's own spec (``docs/superpowers/specs/
2026-09-25-profile-portability-and-community-library-design.md`` section 3.3
in the ``Cognisn/termograph`` repository — this repository does not carry a
copy of that document, only the rule it states):

1. Load the Ed25519 private key from the ``TERMOGRAPH_SIGNING_KEY``
   environment variable.
2. For every ``bundles/*.tgprofile`` file, read its ``manifest.json`` member
   exactly as stored — never re-serialised — check that those stored bytes
   are ALREADY in the canonical form the spec defines (see
   ``canonical_manifest_bytes`` below), sign those exact bytes, and write the
   signature back as the bundle's ``signature`` member.
3. Regenerate ``index.json`` from the signed bundles' own manifests.

**Why step 2 checks canonical form rather than only signing whatever bytes
are there.** Signing is technically indifferent to this — Termograph's own
importer verifies a signature against a bundle's stored ``manifest.json``
bytes directly, never against a re-serialised form, so a non-canonical but
self-consistent manifest would still *verify*. What it would silently break
is Termograph's own "modified since import" check (spec R11), which DOES
re-canonicalise a manifest before hashing it — a bundle whose stored bytes
were never canonical to begin with would appear permanently "modified" to
every deployment that ever imports it, from the moment it lands, which is
a warning nobody would trust. Catching that here, before a bundle is ever
signed and merged, is cheap; catching it after is not, because R11 hashes
the STORED bytes forever once a bundle is published.

``canonical_manifest_bytes`` in this file is a **second, independent
implementation of the spec's rule** — it operates on a plain ``dict`` parsed
by ``json.loads``, never on Termograph's own ``BundleManifest`` model, and
this repository does not import the product package. This is deliberate:
the spec states "a conformance vector belongs beside any second
implementation", and the two implementations agreeing byte-for-byte on that
vector is what ``tests/test_sign.py`` proves. If the two ever disagree, the
first symptom is every signature failing to verify on the product side —
misleading, because the actual defect is a canonicalisation mismatch here,
not a corrupted key. That is why this check exists as a distinct, named
failure mode rather than being left to surface downstream.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import os
import sys
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_private_key

#: Name of the environment variable carrying the private signing key
#: (PEM, or a raw 32-byte seed as hex or base64 — see ``_load_private_key``).
SIGNING_KEY_ENV = "TERMOGRAPH_SIGNING_KEY"

#: The two member names Termograph's importer (``termograph.profiles.bundle.
#: import_``) reads by these exact fixed names. ``signature`` is never a
#: member the manifest's own ``members`` map names — it cannot commit to its
#: own detached signature — so it is handled separately throughout.
MANIFEST_MEMBER = "manifest.json"
PROFILE_MEMBER = "profile.yaml"
SIGNATURE_MEMBER = "signature"

#: The fixed zip timestamp every member is written with, matching the
#: product exporter's own fixed epoch (``termograph.profiles.bundle.export.
#: _ZIP_EPOCH``). Re-signing an unchanged bundle with an unchanged key then
#: reproduces byte-identical output — useful for confirming a re-run of this
#: pipeline changed nothing it should not have.
_ZIP_EPOCH: tuple[int, int, int, int, int, int] = (1980, 1, 1, 0, 0, 0)

#: Where this script expects to find bundles and where it writes the index,
#: both relative to the repository root — the working directory the publish
#: workflow runs it from. Exposed as constants (rather than buried in
#: ``__main__``) so a caller importing this module can see the real
#: defaults without reading past them.
DEFAULT_BUNDLES_DIR = Path("bundles")
DEFAULT_INDEX_PATH = Path("index.json")


class SigningError(RuntimeError):
    """Raised for any condition that must stop the publish pipeline.

    Every raise site names the bundle (or the key) at fault — this is the
    only exception type ``__main__`` catches, and it prints the message
    verbatim as a GitHub Actions ``::error::`` annotation, so the message is
    the whole of what an operator sees.
    """


def canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    """Render *manifest* — an already-parsed ``manifest.json`` dict — as the
    canonical byte form the spec defines: plain lexicographic key sort at
    every nesting level, no insignificant whitespace, literal UTF-8 for
    non-ASCII text, RFC 8259's minimal escaping, integers only, UTF-8
    output. See the module docstring for why this exists as a real,
    load-bearing check rather than a test-only convenience.

    ``json.dumps(..., sort_keys=True)`` already sorts a nested dict's keys
    recursively at every level, not only the top one, and already emits the
    short escape forms (``\\b \\f \\n \\r \\t``) RFC 8259 permits for control
    characters — that is standard library behaviour this function relies on
    rather than reimplements.
    """
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def key_id_of(raw_public_key: bytes) -> str:
    """Return the key id for *raw_public_key*: the first 16 hex characters
    of the SHA-256 of its raw 32 bytes.

    Deliberately mirrors ``termograph.profiles.bundle.signing.key_id_of`` in
    the product repository exactly — see the module docstring's warning
    about what a divergence here would look like (an index advertising a
    key id the product does not recognise, refused wholesale as
    ``unknown_signing_key`` rather than a per-bundle failure). Reimplemented
    rather than imported: this repository does not, and must not, depend on
    the product package.
    """
    return hashlib.sha256(raw_public_key).hexdigest()[:16]


def _load_private_key(raw: str) -> Ed25519PrivateKey:
    """Parse *raw* — the ``TERMOGRAPH_SIGNING_KEY`` value — as an Ed25519
    private key.

    Accepts PEM (PKCS8, e.g. the output of ``openssl genpkey -algorithm
    ed25519``), or a bare 32-byte seed encoded as hex or base64 — whichever
    form the secret happens to be stored in. Tried in that order; the first
    form that parses successfully is used. Never logs, prints, or otherwise
    echoes *raw* or any byte derived from it other than the (public,
    non-secret) key id on any path.
    """
    text = raw.strip()
    if "BEGIN PRIVATE KEY" in text:
        key = load_pem_private_key(text.encode("utf-8"), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise SigningError(f"{SIGNING_KEY_ENV} is a PEM key, but not an Ed25519 private key")
        return key

    compact = "".join(text.split())
    seed: bytes | None = None
    try:
        candidate = bytes.fromhex(compact)
    except ValueError:
        candidate = None
    if candidate is not None and len(candidate) == 32:
        seed = candidate
    if seed is None:
        try:
            candidate = base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError):
            candidate = None
        if candidate is not None and len(candidate) == 32:
            seed = candidate
    if seed is None:
        raise SigningError(
            f"{SIGNING_KEY_ENV} is not a recognised Ed25519 private key "
            "(expected PEM, or a 32-byte seed encoded as hex or base64)"
        )
    return Ed25519PrivateKey.from_private_bytes(seed)


def _read_bundle_members(path: Path) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(path) as zf:
            return {name: zf.read(name) for name in zf.namelist()}
    except zipfile.BadZipFile as exc:
        raise SigningError(f"{path}: not a readable zip archive") from exc


def _write_signed_bundle(path: Path, members: dict[str, bytes], signature: bytes) -> None:
    """Rewrite *path* with every member of *members* (any pre-existing
    ``signature`` member excluded) plus the new *signature*, using the same
    fixed zip metadata the product exporter uses.

    Every OTHER member's bytes are carried through unchanged — this never
    re-derives ``manifest.json``, ``detector.yaml`` or ``profile.yaml``, it
    only relocates their already-read bytes into a fresh archive. Sorting
    member names gives a deterministic member order independent of whatever
    order the *source* zip happened to use, which keeps re-signing
    unchanged content byte-for-byte reproducible.
    """
    ordered = sorted((name, data) for name, data in members.items() if name != SIGNATURE_MEMBER)
    ordered.append((SIGNATURE_MEMBER, signature))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w") as zf:
        for name, data in ordered:
            info = zipfile.ZipInfo(filename=name, date_time=_ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 0
            zf.writestr(info, data)
    path.write_bytes(buffer.getvalue())


def _reject_non_round_tripping_profile(path: Path, members: dict[str, bytes]) -> None:
    """Refuse a bundle whose ``profile.yaml`` is not what a fresh export
    would reproduce.

    This is the manifest's canonical-form check, applied one member over,
    for exactly the reason that one already gives: Termograph compares a
    bundle against the deployment's stored copy by re-exporting the copy
    and hashing it, never by re-serialising the stored bytes. So a
    ``profile.yaml`` whose bytes differ from the exporter's own output —
    even when the CONTENT is identical — hashes differently for ever, and
    every deployment that installs the bundle reads it as "modified since
    import" from the instant it lands.

    That is not theoretical. The ``nuix-7.6-case-family`` 1.1 bundle was
    hand-edited, and the only difference from a fresh export was where
    PyYAML wraps a long description string: identical content, different
    line breaks. Live on tmg-t01 it showed as modified immediately after a
    clean update, while every bundle that had never been hand-edited showed
    as unmodified — and because Termograph now refuses to UPDATE a modified
    profile without an explicit override, a false badge is not merely
    cosmetic: it makes the next update refuse for a profile nobody touched.

    The rule mirrors ``export._profile_member_bytes`` in
    ``Cognisn/termograph``: parse the document, re-dump it with
    ``sort_keys=False, allow_unicode=True``, and require the bytes to
    match. Reimplemented here rather than imported, on the same footing as
    ``canonical_manifest_bytes`` — the two repositories share no artefact,
    so this is a second, independent statement of one rule and the two must
    be kept in step by hand.
    """
    raw = members.get(PROFILE_MEMBER)
    if raw is None:
        raise SigningError(f"{path}: no profile.yaml member")
    try:
        text = raw.decode("utf-8")
        document = yaml.safe_load(text)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise SigningError(f"{path}: profile.yaml is not readable UTF-8 YAML") from exc

    reproduced = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
    if reproduced != text:
        raise SigningError(
            f"{path}: profile.yaml is not what a fresh export would reproduce — its content may "
            "be correct, but its bytes are not, so every deployment installing this bundle would "
            "read it as modified from the moment it landed (and refuse the next update). "
            "Re-export it from Termograph, or normalise it with "
            "yaml.safe_dump(yaml.safe_load(text), sort_keys=False, allow_unicode=True)."
        )


def sign_bundle(path: Path, private_key: Ed25519PrivateKey) -> bytes:
    """Sign *path*'s manifest and rewrite it with a fresh ``signature``
    member. Returns the signed bundle's whole-file bytes (for the caller's
    ``index.json`` ``sha256`` entry, computed once rather than re-read).
    """
    members = _read_bundle_members(path)
    if MANIFEST_MEMBER not in members:
        raise SigningError(f"{path}: no manifest.json member")
    manifest_bytes = members[MANIFEST_MEMBER]

    try:
        manifest_dict = json.loads(manifest_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SigningError(f"{path}: manifest.json is not valid JSON") from exc
    if not isinstance(manifest_dict, dict):
        raise SigningError(f"{path}: manifest.json must be a JSON object")

    expected = canonical_manifest_bytes(manifest_dict)
    if expected != manifest_bytes:
        raise SigningError(
            f"{path}: manifest.json is not already in canonical form — "
            "the exporter that produced this bundle disagrees with the spec's "
            "canonicalisation rule (section 3.3). Refusing to sign a manifest "
            "whose stored bytes are not what a fresh export would reproduce."
        )

    _reject_non_round_tripping_profile(path, members)

    signature = private_key.sign(manifest_bytes)
    _write_signed_bundle(path, members, signature)
    return path.read_bytes()


@dataclass(frozen=True)
class CatalogueEntry:
    """One ``index.json`` bundle entry (``index.schema.json``'s real shape —
    ``id``/``name``/``provider``/``version``/``platforms``/``file``/
    ``sha256`` required, ``slots``/``signed``/``published_at`` optional but
    always set here since every bundle this script indexes was just signed).
    """

    id: str
    name: str
    provider: str
    version: str
    platforms: list[str]
    slots: list[str]
    file: str
    sha256: str
    signed: bool
    published_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider,
            "version": self.version,
            "platforms": self.platforms,
            "slots": self.slots,
            "file": self.file,
            "sha256": self.sha256,
            "signed": self.signed,
            "published_at": self.published_at,
        }


def _entry_for(signed_bytes: bytes, bundles_dir: Path, path: Path, published_at: str) -> CatalogueEntry:
    with zipfile.ZipFile(io.BytesIO(signed_bytes)) as zf:
        manifest = json.loads(zf.read(MANIFEST_MEMBER))
    return CatalogueEntry(
        id=manifest["bundle_id"],
        name=manifest["name"],
        provider=manifest["provider"],
        version=manifest["version"],
        platforms=list(manifest.get("platforms", [])),
        slots=list(manifest.get("slots", [])),
        # index.schema.json's `file` is a path within this repository — the
        # bundles directory's own name joined with the file's basename, not
        # an absolute or caller-local path.
        file=f"{bundles_dir.name}/{path.name}",
        sha256=hashlib.sha256(signed_bytes).hexdigest(),
        signed=True,
        published_at=published_at,
    )


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_index(index_path: Path, entries: list[CatalogueEntry], key_id: str, generated_at: str) -> None:
    document = {
        "schema_version": 1,
        "generated_at": generated_at,
        "signing_key_id": key_id,
        "bundles": [entry.as_dict() for entry in sorted(entries, key=lambda e: e.id)],
    }
    index_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def main(
    bundles_dir: Path = DEFAULT_BUNDLES_DIR,
    index_path: Path = DEFAULT_INDEX_PATH,
    *,
    signing_key: str | None = None,
) -> None:
    """Sign every ``bundles_dir/*.tgprofile`` and (re)write *index_path*.

    *signing_key* defaults to the ``TERMOGRAPH_SIGNING_KEY`` environment
    variable — the real pipeline's path. Accepting it as a parameter, too,
    is what lets a test drive this with a freshly generated, disposable key
    without ever touching the real secret or the environment.
    """
    raw_key = signing_key if signing_key is not None else os.environ.get(SIGNING_KEY_ENV)
    if not raw_key:
        raise SigningError(f"{SIGNING_KEY_ENV} is not set")
    private_key = _load_private_key(raw_key)
    raw_public = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = key_id_of(raw_public)
    print(f"signing with key id {key_id}")

    bundle_paths = sorted(bundles_dir.glob("*.tgprofile"))
    generated_at = _now_iso()
    entries: list[CatalogueEntry] = []
    for path in bundle_paths:
        signed_bytes = sign_bundle(path, private_key)
        entry = _entry_for(signed_bytes, bundles_dir, path, generated_at)
        entries.append(entry)
        print(f"signed {path.name} ({entry.id} {entry.version}) sha256={entry.sha256}")

    _write_index(index_path, entries, key_id, generated_at)
    print(f"wrote {index_path} with {len(entries)} bundle(s)")


if __name__ == "__main__":
    try:
        main()
    except SigningError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        sys.exit(1)

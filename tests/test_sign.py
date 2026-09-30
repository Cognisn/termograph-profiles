"""Tests for tools/sign.py: the publish pipeline's signing and indexing step.

Two things matter most here, and both are named directly in the module
under test's own docstring:

1. ``canonical_manifest_bytes`` — this repository's own, independent
   implementation of the spec's canonicalisation rule — must agree
   byte-for-byte with the product repository's ``termograph.profiles.
   bundle.manifest.canonical_manifest_bytes`` on the SAME conformance
   vector. ``test_canonical_manifest_bytes_matches_the_spec_conformance_vector``
   is this repository's half of that agreement; the product repository's
   mirror lives in ``tests/profiles/bundle/test_manifest_conformance_vector.py``
   there, and the full end-to-end proof — a bundle this repository's own
   tooling signs verifying through the product's own ``verify_manifest`` —
   lives in that same product-side test module.
2. ``key_id_of`` must agree with ``termograph.profiles.bundle.signing.
   key_id_of`` exactly, or every index this pipeline writes advertises a
   key id the product cannot match.

No test in this file uses, generates from, or otherwise touches the real
signing key. Every test that needs a private key generates its own
disposable Ed25519 key pair.
"""

from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from pathlib import Path

import pytest
import sign
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# ---------------------------------------------------------------------------
# The conformance vector -- byte-for-byte identical to the one recorded in
# docs/superpowers/specs/2026-09-25-profile-portability-and-community-
# library-design.md section 3.3 in the product repository, and to
# tests/profiles/bundle/test_manifest_conformance_vector.py there. Copied as
# a literal constant here too, deliberately -- NOT re-derived from calling
# sign.canonical_manifest_bytes -- so this test can only pass if this
# repository's real output matches what the spec states, not merely what
# this run of the function happens to produce.
# ---------------------------------------------------------------------------

_VECTOR_MANIFEST_DICT = {
    "bundle_id": "vector.manifest",
    "name": 'Vector "Alpha" \\ Beta',
    "provider": "Ångström Forensics 株式会社",
    "version": "1.0.0",
    "format_version": 1,
    "platforms": ["Nuix Workstation 7.x", "Relativity"],
    # Inserted in the OPPOSITE order to their sorted order (profile.yaml
    # before detector.yaml), so a passing test proves key sorting is really
    # happening rather than insertion order coincidentally already matching.
    "members": {
        "profile.yaml": "sha256:" + "1" * 64,
        "detector.yaml": "sha256:" + "2" * 64,
    },
    "slots": [],
}

_VECTOR_BYTES = (
    b'{"bundle_id":"vector.manifest","format_version":1,"members":{"detector.yaml":'
    b'"sha256:2222222222222222222222222222222222222222222222222222222222222222",'
    b'"profile.yaml":"sha256:1111111111111111111111111111111111111111111111111111'
    b'111111111111"},"name":"Vector \\"Alpha\\" \\\\ Beta","platforms":["Nuix Work'
    b'station 7.x","Relativity"],"provider":"\xc3\x85ngstr\xc3\xb6m Forensics \xe6'
    b'\xa0\xaa\xe5\xbc\x8f\xe4\xbc\x9a\xe7\xa4\xbe","slots":[],"version":"1.0.0"}'
)

_VECTOR_SHA256 = "08d90c083f28b89fe1704777199167da3aa6cb0e6c8c8c4f96981777ebc2ff3d"


def test_canonical_manifest_bytes_matches_the_spec_conformance_vector() -> None:
    produced = sign.canonical_manifest_bytes(_VECTOR_MANIFEST_DICT)
    assert produced == _VECTOR_BYTES
    assert hashlib.sha256(produced).hexdigest() == _VECTOR_SHA256


def test_canonical_manifest_bytes_sorts_nested_keys_though_inserted_reversed() -> None:
    produced = sign.canonical_manifest_bytes(_VECTOR_MANIFEST_DICT)
    detector_index = produced.index(b'"detector.yaml"')
    profile_index = produced.index(b'"profile.yaml"')
    assert detector_index < profile_index


def test_canonical_manifest_bytes_emits_non_ascii_literally_not_as_uxxxx() -> None:
    produced = sign.canonical_manifest_bytes(_VECTOR_MANIFEST_DICT)
    assert b"\\u" not in produced
    assert "Ångström Forensics 株式会社".encode() in produced


# ---------------------------------------------------------------------------
# key_id_of
# ---------------------------------------------------------------------------


def test_key_id_of_matches_the_documented_library_key_id() -> None:
    # The real, embedded LIBRARY_PUBLIC_KEY from termograph.profiles.bundle.
    # signing in the product repository -- pinned as a literal constant here
    # too (not imported; this repository must not depend on the product
    # package) so a derivation disagreement is caught on THIS side as well.
    raw = bytes.fromhex("532c26ce50c7e5353e49fbef7d6ed521ae341ab8dec7eaabf6dfc404bb16706f")
    assert sign.key_id_of(raw) == "80ef9190a7ccf66f"


def test_key_id_of_is_first_16_hex_chars_of_sha256() -> None:
    raw = b"\x00" * 32
    expected = hashlib.sha256(raw).hexdigest()[:16]
    assert sign.key_id_of(raw) == expected
    assert len(sign.key_id_of(raw)) == 16


# ---------------------------------------------------------------------------
# _load_private_key -- every format sign.py must be able to read
# ---------------------------------------------------------------------------


def _ephemeral_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def test_load_private_key_accepts_pem() -> None:
    key = _ephemeral_key()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode("ascii")
    loaded = sign._load_private_key(pem)
    assert loaded.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )


def test_load_private_key_accepts_raw_hex() -> None:
    key = _ephemeral_key()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    loaded = sign._load_private_key(seed.hex())
    assert loaded.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )


def test_load_private_key_accepts_base64() -> None:
    key = _ephemeral_key()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    loaded = sign._load_private_key(base64.b64encode(seed).decode("ascii"))
    assert loaded.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) == key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )


def test_load_private_key_rejects_an_unrecognised_format() -> None:
    with pytest.raises(sign.SigningError, match="not a recognised Ed25519"):
        sign._load_private_key("clearly not a key")


# ---------------------------------------------------------------------------
# sign_bundle / main -- built entirely on ephemeral keys and hand-built
# fixture bundles, never the real bundle shape from the product exporter
# (this repository does not import the product package), but exercising the
# real zip member names (manifest.json / signature) the product's importer
# reads.
# ---------------------------------------------------------------------------


def _write_unsigned_bundle(path: Path, *, bundle_id: str = "fixture-bundle") -> bytes:
    """Write a minimal, ALREADY-CANONICAL unsigned .tgprofile at *path* and
    return its manifest.json bytes."""
    detector_bytes = b"kind: detector\nid: fixture-detector\n"
    profile_bytes = b"kind: collection_profile\nid: fixture-profile\n"
    manifest_dict = {
        "bundle_id": bundle_id,
        "name": "Fixture bundle",
        "provider": "Test harness",
        "version": "1.0.0",
        "format_version": 1,
        "platforms": ["Nuix Workstation 7.x"],
        "members": {
            "detector.yaml": "sha256:" + hashlib.sha256(detector_bytes).hexdigest(),
            "profile.yaml": "sha256:" + hashlib.sha256(profile_bytes).hexdigest(),
        },
        "slots": ["pairing"],
    }
    manifest_bytes = sign.canonical_manifest_bytes(manifest_dict)
    with zipfile.ZipFile(path, mode="w") as zf:
        zf.writestr("detector.yaml", detector_bytes)
        zf.writestr("profile.yaml", profile_bytes)
        zf.writestr("manifest.json", manifest_bytes)
    return manifest_bytes


def test_sign_bundle_produces_a_signature_that_verifies_against_the_public_key(tmp_path: Path) -> None:
    key = _ephemeral_key()
    bundle_path = tmp_path / "fixture-1.0.0.tgprofile"
    manifest_bytes = _write_unsigned_bundle(bundle_path)

    sign.sign_bundle(bundle_path, key)

    with zipfile.ZipFile(bundle_path) as zf:
        assert zf.read("manifest.json") == manifest_bytes  # untouched by signing
        signature = zf.read("signature")
    assert len(signature) == 64
    key.public_key().verify(signature, manifest_bytes)  # raises InvalidSignature on failure


def test_sign_bundle_signature_does_not_verify_against_a_different_key(tmp_path: Path) -> None:
    key = _ephemeral_key()
    other_key = _ephemeral_key()
    bundle_path = tmp_path / "fixture-1.0.0.tgprofile"
    _write_unsigned_bundle(bundle_path)

    sign.sign_bundle(bundle_path, key)

    with zipfile.ZipFile(bundle_path) as zf:
        manifest_bytes = zf.read("manifest.json")
        signature = zf.read("signature")
    with pytest.raises(InvalidSignature):
        other_key.public_key().verify(signature, manifest_bytes)


def test_sign_bundle_refuses_a_non_canonical_manifest(tmp_path: Path) -> None:
    key = _ephemeral_key()
    bundle_path = tmp_path / "fixture-1.0.0.tgprofile"
    _write_unsigned_bundle(bundle_path)

    # Mutate manifest.json in place to a semantically-equal but
    # NON-canonical form (added whitespace) -- exactly the shape a broken or
    # non-standard exporter could produce.
    with zipfile.ZipFile(bundle_path) as zf:
        members = {name: zf.read(name) for name in zf.namelist()}
    broken = json.dumps(json.loads(members["manifest.json"]), indent=2).encode("utf-8")
    with zipfile.ZipFile(bundle_path, mode="w") as zf:
        zf.writestr("detector.yaml", members["detector.yaml"])
        zf.writestr("profile.yaml", members["profile.yaml"])
        zf.writestr("manifest.json", broken)

    with pytest.raises(sign.SigningError, match="not already in canonical form"):
        sign.sign_bundle(bundle_path, key)


def test_sign_bundle_missing_manifest_is_refused(tmp_path: Path) -> None:
    key = _ephemeral_key()
    bundle_path = tmp_path / "empty.tgprofile"
    with zipfile.ZipFile(bundle_path, mode="w") as zf:
        zf.writestr("detector.yaml", b"kind: detector\n")

    with pytest.raises(sign.SigningError, match="no manifest.json member"):
        sign.sign_bundle(bundle_path, key)


def test_re_signing_an_already_signed_bundle_replaces_the_stale_signature(tmp_path: Path) -> None:
    # A bundle can genuinely reach sign_bundle a second time already
    # carrying a signature member -- a re-triggered workflow run, or a
    # contributor's pull request updated after a first (never-merged) pass.
    # The stale entry must be REPLACED, not appended alongside the fresh
    # one (which would leave two `signature` members and an ambiguous
    # bundle), and the fresh signature must genuinely be a new one made by
    # whichever key signed it this time, not a leftover.
    old_key = _ephemeral_key()
    new_key = _ephemeral_key()
    bundle_path = tmp_path / "fixture-1.0.0.tgprofile"
    _write_unsigned_bundle(bundle_path)

    sign.sign_bundle(bundle_path, old_key)
    with zipfile.ZipFile(bundle_path) as zf:
        assert zf.namelist().count(sign.SIGNATURE_MEMBER) == 1
        manifest_before = zf.read("manifest.json")
        stale_signature = zf.read(sign.SIGNATURE_MEMBER)

    # Re-sign the SAME already-signed bundle with a DIFFERENT key.
    sign.sign_bundle(bundle_path, new_key)

    with zipfile.ZipFile(bundle_path) as zf:
        names_after = zf.namelist()
        manifest_after = zf.read("manifest.json")
        fresh_signature = zf.read(sign.SIGNATURE_MEMBER)

    # No duplicate signature member -- the stale one was replaced, not
    # appended alongside the fresh one.
    assert names_after.count(sign.SIGNATURE_MEMBER) == 1
    # manifest.json itself is untouched by re-signing.
    assert manifest_after == manifest_before
    # The stale signature is genuinely gone, not merely shadowed in
    # ordering by a duplicate entry.
    assert fresh_signature != stale_signature
    # The surviving signature verifies against the NEW key...
    new_key.public_key().verify(fresh_signature, manifest_after)
    # ...the stale signature does not verify under the new key (it was
    # made by a different key, confirming what "stale" means here)...
    with pytest.raises(InvalidSignature):
        new_key.public_key().verify(stale_signature, manifest_after)
    # ...and the fresh signature does not verify under the OLD key either
    # (it is a genuinely new signature, not the old one merely reordered).
    with pytest.raises(InvalidSignature):
        old_key.public_key().verify(fresh_signature, manifest_after)


def test_main_regenerates_index_with_the_real_schema_shape(tmp_path: Path) -> None:
    key = _ephemeral_key()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode("ascii")
    raw_public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    expected_key_id = sign.key_id_of(raw_public)

    bundles_dir = tmp_path / "bundles"
    bundles_dir.mkdir()
    _write_unsigned_bundle(bundles_dir / "fixture-1.0.0.tgprofile", bundle_id="fixture-bundle")
    index_path = tmp_path / "index.json"

    sign.main(bundles_dir, index_path, signing_key=pem)

    index = json.loads(index_path.read_text(encoding="utf-8"))
    assert index["schema_version"] == 1
    assert index["signing_key_id"] == expected_key_id
    assert index["generated_at"] is not None
    assert len(index["bundles"]) == 1
    entry = index["bundles"][0]
    # Exactly the real schema's required fields, per index.schema.json.
    for required in ("id", "name", "provider", "version", "platforms", "file", "sha256"):
        assert required in entry
    assert entry["id"] == "fixture-bundle"
    assert entry["file"] == "bundles/fixture-1.0.0.tgprofile"
    assert entry["signed"] is True
    assert entry["sha256"] == hashlib.sha256((bundles_dir / "fixture-1.0.0.tgprofile").read_bytes()).hexdigest()


def test_main_with_no_bundles_still_writes_a_valid_empty_index(tmp_path: Path) -> None:
    key = _ephemeral_key()
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode("ascii")

    bundles_dir = tmp_path / "bundles"
    bundles_dir.mkdir()
    index_path = tmp_path / "index.json"

    sign.main(bundles_dir, index_path, signing_key=pem)

    index = json.loads(index_path.read_text(encoding="utf-8"))
    assert index["schema_version"] == 1
    assert index["bundles"] == []
    assert index["signing_key_id"] == sign.key_id_of(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def test_main_raises_when_no_signing_key_is_available(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(sign.SIGNING_KEY_ENV, raising=False)
    bundles_dir = tmp_path / "bundles"
    bundles_dir.mkdir()
    with pytest.raises(sign.SigningError, match=f"{sign.SIGNING_KEY_ENV} is not set"):
        sign.main(bundles_dir, tmp_path / "index.json")


def test_two_signing_runs_of_unchanged_content_with_the_same_key_are_byte_identical(tmp_path: Path) -> None:
    # Ed25519 signatures are deterministic (RFC 8032) -- re-running the
    # pipeline over unchanged bundles with the same key must reproduce
    # byte-identical output, so a no-op merge to main does not churn the
    # index or the bundle files for no reason.
    key = _ephemeral_key()

    bundles_dir = tmp_path / "bundles"
    bundles_dir.mkdir()
    _write_unsigned_bundle(bundles_dir / "fixture-1.0.0.tgprofile")
    first_bytes = sign.sign_bundle(bundles_dir / "fixture-1.0.0.tgprofile", key)

    # Reset to an unsigned bundle and sign again.
    _write_unsigned_bundle(bundles_dir / "fixture-1.0.0.tgprofile")
    second_bytes = sign.sign_bundle(bundles_dir / "fixture-1.0.0.tgprofile", key)

    assert first_bytes == second_bytes


def test_sign_bundle_refuses_a_profile_yaml_a_fresh_export_would_not_reproduce(tmp_path: Path) -> None:
    """The manifest's canonical-form rule, one member over.

    Termograph decides "has this been modified since import?" by
    re-exporting the deployment's stored copy and hashing it, never by
    re-serialising the bundle's stored bytes. So a profile.yaml whose bytes
    differ from the exporter's own output hashes differently for ever, and
    every deployment installing the bundle reads it as modified from the
    moment it lands.

    Observed live on tmg-t01: the hand-edited nuix-7.6-case-family 1.1
    bundle differed from a fresh export only in where PyYAML wraps a long
    description string — identical content, different line breaks — and
    showed as modified immediately after a clean update, while every
    never-hand-edited bundle showed as unmodified. That is not merely a
    false badge: Termograph refuses to UPDATE a modified profile without an
    explicit override, so it makes the next update refuse for a profile
    nobody touched.

    The fixture below is valid YAML carrying the right content and the
    right hash — the ONLY thing wrong with it is its line breaks, which is
    exactly the case that slipped through.
    """
    key = _ephemeral_key()
    bundle_path = tmp_path / "wrapped-1.0.0.tgprofile"

    detector_bytes = b"kind: detector\nid: fixture-detector\n"
    # A long value hand-wrapped at a different column from PyYAML's own
    # default. yaml.safe_load gives the identical string either way.
    profile_bytes = (
        "kind: collection_profile\n"
        "id: fixture-profile\n"
        "description: 'A description long enough that the dumper must wrap it somewhere,\n"
        "  wrapped here by hand at a column the dumper would not have chosen for itself.'\n"
    ).encode("utf-8")

    manifest_dict = {
        "bundle_id": "wrapped",
        "name": "Hand-wrapped bundle",
        "provider": "Test harness",
        "version": "1.0.0",
        "format_version": 1,
        "platforms": ["Nuix Workstation 7.x"],
        "members": {
            "detector.yaml": "sha256:" + hashlib.sha256(detector_bytes).hexdigest(),
            "profile.yaml": "sha256:" + hashlib.sha256(profile_bytes).hexdigest(),
        },
        "slots": ["pairing"],
    }
    with zipfile.ZipFile(bundle_path, mode="w") as zf:
        zf.writestr("detector.yaml", detector_bytes)
        zf.writestr("profile.yaml", profile_bytes)
        zf.writestr("manifest.json", sign.canonical_manifest_bytes(manifest_dict))

    with pytest.raises(sign.SigningError, match="not what a fresh export would reproduce"):
        sign.sign_bundle(bundle_path, key)


def test_sign_bundle_accepts_a_profile_yaml_the_exporter_itself_produced(tmp_path: Path) -> None:
    """The other half: normalising the same content must make it signable,
    so the refusal above is about bytes and not about the content."""
    import yaml

    key = _ephemeral_key()
    bundle_path = tmp_path / "normalised-1.0.0.tgprofile"

    detector_bytes = b"kind: detector\nid: fixture-detector\n"
    hand_wrapped = (
        "kind: collection_profile\n"
        "id: fixture-profile\n"
        "description: 'A description long enough that the dumper must wrap it somewhere,\n"
        "  wrapped here by hand at a column the dumper would not have chosen for itself.'\n"
    )
    normalised = yaml.safe_dump(yaml.safe_load(hand_wrapped), sort_keys=False, allow_unicode=True)
    assert yaml.safe_load(normalised) == yaml.safe_load(hand_wrapped), "content must be unchanged"
    profile_bytes = normalised.encode("utf-8")

    manifest_dict = {
        "bundle_id": "normalised",
        "name": "Normalised bundle",
        "provider": "Test harness",
        "version": "1.0.0",
        "format_version": 1,
        "platforms": ["Nuix Workstation 7.x"],
        "members": {
            "detector.yaml": "sha256:" + hashlib.sha256(detector_bytes).hexdigest(),
            "profile.yaml": "sha256:" + hashlib.sha256(profile_bytes).hexdigest(),
        },
        "slots": ["pairing"],
    }
    with zipfile.ZipFile(bundle_path, mode="w") as zf:
        zf.writestr("detector.yaml", detector_bytes)
        zf.writestr("profile.yaml", profile_bytes)
        zf.writestr("manifest.json", sign.canonical_manifest_bytes(manifest_dict))

    sign.sign_bundle(bundle_path, key)
    assert "signature" in zipfile.ZipFile(bundle_path).namelist()

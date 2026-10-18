"""Unit tests for OpenTimestamps anchor backend (SPEC_PHASE3 §1, T-22).

All tests use deterministic mocks; NO real network calls are executed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from r0nt.anchor import AttestationStatus, FakeBackend
from r0nt.anchor_backends import (
    DEFAULT_CALENDAR_URLS,
    OpenTimestampsBackend,
    get_anchor_backend,
    is_opentimestamps_available,
)


def _make_ots_proof(
    digest: bytes,
    attestation_type: str = "pending",
    block_height: int = 850000,
    calendar_uri: str = "https://a.pool.opentimestamps.org",
) -> bytes:
    """Helper to construct deterministic serialized OTS bytes without network."""
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
    from opentimestamps.core.op import OpSHA256
    from opentimestamps.core.serialize import BytesSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

    ts = Timestamp(digest)
    if attestation_type == "pending":
        ts.attestations.add(PendingAttestation(calendar_uri))
    elif attestation_type == "confirmed":
        ts.attestations.add(BitcoinBlockHeaderAttestation(block_height))
    else:
        raise ValueError(f"Unknown attestation_type: {attestation_type}")

    detached = DetachedTimestampFile(OpSHA256(), ts)
    ctx = BytesSerializationContext()
    detached.serialize(ctx)
    return ctx.getbytes()


def test_is_opentimestamps_available():
    # In current development environment with opentimestamps installed
    assert is_opentimestamps_available() is True

    # Test graceful fallback when import fails
    with patch.dict("sys.modules", {"opentimestamps.calendar": None}):
        assert is_opentimestamps_available() is False


def test_get_anchor_backend_factory():
    fake = get_anchor_backend("fake")
    assert isinstance(fake, FakeBackend)

    ots = get_anchor_backend("ots")
    assert isinstance(ots, OpenTimestampsBackend)

    with pytest.raises(ValueError, match="Unknown anchor backend"):
        get_anchor_backend("nonexistent_backend")


def test_ots_backend_import_error_when_unavailable():
    with patch("r0nt.anchor_backends.is_opentimestamps_available", return_value=False):
        with pytest.raises(ImportError, match="requires the 'opentimestamps' package"):
            OpenTimestampsBackend()


def test_ots_backend_submit_mocked():
    digest = b"\x11" * 32

    backend = OpenTimestampsBackend(calendar_urls=["https://a.pool.opentimestamps.org"])

    from opentimestamps.core.notary import PendingAttestation
    from opentimestamps.core.serialize import BytesDeserializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

    mock_ts = Timestamp(digest)
    mock_ts.attestations.add(PendingAttestation("https://a.pool.opentimestamps.org"))

    with patch("opentimestamps.calendar.RemoteCalendar.submit", return_value=mock_ts):
        proof = backend.submit(digest)

    assert isinstance(proof, bytes)
    assert len(proof) > 0

    detached = DetachedTimestampFile.deserialize(BytesDeserializationContext(proof))
    assert detached.file_digest == digest


def test_ots_backend_submit_network_failure():
    digest = b"\x22" * 32
    backend = OpenTimestampsBackend(calendar_urls=["https://a.pool.opentimestamps.org"])

    with patch("opentimestamps.calendar.RemoteCalendar.submit", side_effect=OSError("Network unreachable")):
        with pytest.raises(ConnectionError, match="Failed to submit digest to any OpenTimestamps calendar"):
            backend.submit(digest)


def test_ots_backend_submit_invalid_digest_length():
    backend = OpenTimestampsBackend()
    with pytest.raises(ValueError, match="Digest must be exactly 32 bytes"):
        backend.submit(b"short_digest")


def test_ots_backend_verify_pending_and_confirmed():
    digest = b"\x33" * 32
    backend = OpenTimestampsBackend()

    # 1. Pending proof
    pending_proof = _make_ots_proof(digest, attestation_type="pending")
    status = backend.verify(pending_proof, digest)
    assert status == AttestationStatus.VALID_PENDING

    # 2. Confirmed proof
    confirmed_proof = _make_ots_proof(digest, attestation_type="confirmed")
    status = backend.verify(confirmed_proof, digest)
    assert status == AttestationStatus.VALID_CONFIRMED

    # 3. Digest mismatch
    wrong_digest = b"\x44" * 32
    status = backend.verify(confirmed_proof, wrong_digest)
    assert status == AttestationStatus.INVALID

    # 4. Corrupted proof bytes
    status = backend.verify(b"NOT_A_VALID_PROOF_HEADER", digest)
    assert status == AttestationStatus.INVALID

    # 5. Empty inputs
    assert backend.verify(b"", digest) == AttestationStatus.INVALID
    assert backend.verify(confirmed_proof, b"short") == AttestationStatus.INVALID


def test_ots_backend_upgrade_workflow():
    digest = b"\x55" * 32
    calendar_uri = "https://a.pool.opentimestamps.org"
    backend = OpenTimestampsBackend(calendar_urls=[calendar_uri])

    pending_proof = _make_ots_proof(digest, attestation_type="pending", calendar_uri=calendar_uri)

    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.timestamp import Timestamp

    upgraded_sub_ts = Timestamp(digest)
    upgraded_sub_ts.attestations.add(BitcoinBlockHeaderAttestation(850000))

    # Case A: Calendar returns upgraded timestamp with bitcoin attestation
    with patch("opentimestamps.calendar.RemoteCalendar.get_timestamp", return_value=upgraded_sub_ts):
        upgraded_proof = backend.upgrade(pending_proof)

    assert upgraded_proof is not None
    assert backend.verify(upgraded_proof, digest) == AttestationStatus.VALID_CONFIRMED

    # Case B: Calendar still pending (raises KeyError / not yet ready)
    with patch("opentimestamps.calendar.RemoteCalendar.get_timestamp", side_effect=KeyError("Commitment not found")):
        assert backend.upgrade(pending_proof) is None

    # Case C: Upgrade on already confirmed proof (no pending attestations left)
    assert backend.upgrade(upgraded_proof) is None

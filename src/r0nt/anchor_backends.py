"""OpenTimestamps external anchor backend implementation (SPEC_PHASE3 §1, T-22).

Implements the AnchorBackend interface for real Bitcoin/calendar timestamping
via the opentimestamps package. The package is an optional dependency; r0nt
runs fully without it using FakeBackend or offline mode.
"""

from __future__ import annotations

import logging
from typing import Any

from r0nt.anchor import AnchorBackend, AttestationStatus, FakeBackend

logger = logging.getLogger(__name__)

# Default public calendar aggregators
DEFAULT_CALENDAR_URLS: tuple[str, ...] = (
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
)


def is_opentimestamps_available() -> bool:
    """Check if the opentimestamps library is installed and importable."""
    try:
        import opentimestamps.calendar  # noqa: F401
        import opentimestamps.core.notary  # noqa: F401
        import opentimestamps.core.op  # noqa: F401
        import opentimestamps.core.serialize  # noqa: F401
        import opentimestamps.core.timestamp  # noqa: F401
        return True
    except (ImportError, Exception):
        return False


class OpenTimestampsBackend(AnchorBackend):
    """External anchoring backend that commits batch roots via OpenTimestamps.

    Submits roots to public calendar servers that aggregate commitments
    and periodically anchor them into Bitcoin blocks.
    """

    def __init__(
        self,
        calendar_urls: tuple[str, ...] | list[str] | None = None,
        timeout: int = 15,
    ) -> None:
        if not is_opentimestamps_available():
            raise ImportError(
                "The OpenTimestamps backend requires the 'opentimestamps' package. "
                "Install it via 'pip install opentimestamps'."
            )

        self.calendar_urls = tuple(calendar_urls) if calendar_urls else DEFAULT_CALENDAR_URLS
        self.timeout = timeout

    def submit(self, digest: bytes) -> bytes:
        """Submit a 32-byte digest to calendar servers and return serialized proof."""
        if len(digest) != 32:
            raise ValueError(f"Digest must be exactly 32 bytes, got {len(digest)}")

        from opentimestamps.calendar import RemoteCalendar
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.serialize import BytesSerializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile

        merged_ts = None
        errors: list[str] = []

        for url in self.calendar_urls:
            try:
                cal = RemoteCalendar(url)
                cal_ts = cal.submit(digest, timeout=self.timeout)
                if merged_ts is None:
                    merged_ts = cal_ts
                else:
                    merged_ts.merge(cal_ts)
            except Exception as exc:
                errors.append(f"{url}: {exc}")

        if merged_ts is None:
            raise ConnectionError(
                f"Failed to submit digest to any OpenTimestamps calendar: {'; '.join(errors)}"
            )

        detached = DetachedTimestampFile(OpSHA256(), merged_ts)
        s_ctx = BytesSerializationContext()
        detached.serialize(s_ctx)
        return s_ctx.getbytes()

    def upgrade(self, proof: bytes) -> bytes | None:
        """Query calendar servers for confirmed blockchain attestations."""
        if not proof:
            return None

        from opentimestamps.calendar import RemoteCalendar
        from opentimestamps.core.notary import PendingAttestation
        from opentimestamps.core.serialize import BytesDeserializationContext, BytesSerializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile

        try:
            d_ctx = BytesDeserializationContext(proof)
            detached = DetachedTimestampFile.deserialize(d_ctx)
        except Exception as exc:
            logger.warning("Failed to deserialize proof for upgrade: %s", exc)
            return None

        pending_items: list[tuple[bytes, PendingAttestation]] = []
        for msg, attestation in detached.timestamp.all_attestations():
            if isinstance(attestation, PendingAttestation):
                pending_items.append((msg, attestation))

        if not pending_items:
            return None

        changed = False
        for msg, pending_att in pending_items:
            try:
                cal = RemoteCalendar(pending_att.uri)
                upgraded_ts = cal.get_timestamp(msg, timeout=self.timeout)
                if upgraded_ts is not None:
                    detached.timestamp.merge(upgraded_ts)
                    changed = True
            except Exception:
                # Calendar not yet confirmed or temporary network issue
                continue

        if changed:
            s_ctx = BytesSerializationContext()
            detached.serialize(s_ctx)
            return s_ctx.getbytes()

        return None

    def verify(self, proof: bytes, digest: bytes) -> AttestationStatus:
        """Verify that proof commits to digest and check attestation status."""
        if not proof or len(digest) != 32:
            return AttestationStatus.INVALID

        from opentimestamps.core.notary import (
            BitcoinBlockHeaderAttestation,
            LitecoinBlockHeaderAttestation,
            PendingAttestation,
        )
        from opentimestamps.core.serialize import BytesDeserializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile

        try:
            d_ctx = BytesDeserializationContext(proof)
            detached = DetachedTimestampFile.deserialize(d_ctx)
        except Exception:
            return AttestationStatus.INVALID

        if detached.file_digest != digest:
            return AttestationStatus.INVALID

        all_atts = list(detached.timestamp.all_attestations())
        if not all_atts:
            return AttestationStatus.INVALID

        # Check for confirmed blockchain block header attestation
        has_confirmed = any(
            isinstance(att, (BitcoinBlockHeaderAttestation, LitecoinBlockHeaderAttestation))
            for _, att in all_atts
        )
        if has_confirmed:
            return AttestationStatus.VALID_CONFIRMED

        # Check for pending calendar attestation
        has_pending = any(
            isinstance(att, PendingAttestation)
            for _, att in all_atts
        )
        if has_pending:
            return AttestationStatus.VALID_PENDING

        return AttestationStatus.INVALID


def get_anchor_backend(name: str = "fake", **kwargs: Any) -> AnchorBackend:
    """Factory for instantiating an anchor backend by name.

    Supports:
        'fake': In-memory deterministic simulator for tests / offline.
        'ots' / 'opentimestamps': Real OpenTimestamps network backend.
    """
    key = name.lower().strip()
    if key in ("fake", "mock", "test"):
        return FakeBackend(**kwargs)
    elif key in ("ots", "opentimestamps", "real"):
        return OpenTimestampsBackend(**kwargs)
    else:
        raise ValueError(
            f"Unknown anchor backend '{name}'. Supported options: 'fake', 'ots'."
        )

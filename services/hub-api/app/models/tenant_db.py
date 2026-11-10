"""Tenant-scoped data access over penguin-dal.

Every read/write is ANDed with ``tenant_id``; inserts stamp tenant_id and public_id;
FK references are checked to belong to the same tenant. Callers cannot opt out.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from penguin_dal import DB, Query, Row

from app.models.schema import ENTITY_TABLES, metadata

_PROTECTED = frozenset({"id", "public_id", "tenant_id", "created_at", "updated_at"})


class TenantViolationError(Exception):
    """Raised when an operation would cross or bypass the tenant boundary."""


class TenantDB:
    """A penguin-dal DB view bound to one tenant; the only data-layer entry point."""

    __slots__ = ("_db", "_tenant_id")

    def __init__(self, db: DB, tenant_id: int) -> None:
        """Bind ``db`` to ``tenant_id``, a positive int taken from the validated token."""
        if isinstance(tenant_id, bool) or not isinstance(tenant_id, int) or tenant_id <= 0:
            raise TenantViolationError("tenant_id must be a positive integer")
        self._db = db
        self._tenant_id = tenant_id

    @property
    def tenant_id(self) -> int:
        """Return the bound tenant id."""
        return self._tenant_id

    def _table(self, name: str) -> Any:
        """Return the penguin-dal table proxy, rejecting unknown tables."""
        if name not in ENTITY_TABLES:
            raise TenantViolationError(f"unknown table {name!r}")
        return getattr(self._db, name)

    def _scope(self, table: str, query: Query | None) -> Query:
        """AND the tenant predicate into ``query``."""
        scoped: Query = self._table(table).tenant_id == self._tenant_id
        return scoped if query is None else scoped & query

    def field(self, table: str, column: str) -> Any:
        """Return a FieldProxy for building queries against ``table.column``."""
        return getattr(self._table(table), column)

    def _check_writable(self, values: dict[str, Any]) -> None:
        """Reject writes to identity/tenant/timestamp columns."""
        bad = _PROTECTED.intersection(values)
        if bad:
            raise TenantViolationError(f"protected columns: {sorted(bad)}")

    def _check_fks(self, table: str, values: dict[str, Any]) -> None:
        """Ensure every non-null FK value references a row in this tenant."""
        for fk in metadata.tables[table].foreign_keys:
            value = values.get(fk.parent.name)
            if value is None:
                continue
            target = fk.column.table.name
            q = self._scope(target, self._table(target).id == value)
            if not self._db(q).exists():
                raise TenantViolationError(f"{fk.parent.name} not found in tenant")

    def insert(self, table: str, /, **values: Any) -> Row:
        """Insert a row stamped with tenant_id and a fresh public_id; return it."""
        self._check_writable(values)
        self._check_fks(table, values)
        public_id = uuid.uuid4()
        self._table(table).insert(tenant_id=self._tenant_id, public_id=public_id, **values)
        row = self.get(table, public_id)
        assert row is not None  # noqa: S101 - just inserted in this tenant
        return row

    def select(
        self,
        table: str,
        query: Query | None = None,
        *,
        orderby: Any = None,
        limitby: tuple[int, int] | None = None,
    ) -> list[Row]:
        """Select rows within the tenant, ordered by ``orderby`` (default id)."""
        order = orderby if orderby is not None else self._table(table).id
        return list(self._db(self._scope(table, query)).select(orderby=order, limitby=limitby))

    def get(self, table: str, public_id: uuid.UUID) -> Row | None:
        """Return the tenant's row with ``public_id``, or None (never another tenant's)."""
        rows = self.select(table, self._table(table).public_id == public_id)
        return rows[0] if rows else None

    def get_by_id(self, table: str, row_id: int) -> Row | None:
        """Return the tenant's row with internal PK ``row_id``, or None."""
        rows = self.select(table, self._table(table).id == row_id)
        return rows[0] if rows else None

    def update(self, table: str, public_id: uuid.UUID, /, **values: Any) -> int:
        """Update the tenant's row by public_id, bumping updated_at; return rowcount."""
        self._check_writable(values)
        self._check_fks(table, values)
        q = self._scope(table, self._table(table).public_id == public_id)
        return int(self._db(q).update(updated_at=datetime.now(UTC), **values))

    def delete(self, table: str, query: Query | None = None) -> int:
        """Delete tenant rows matching ``query``; return rowcount."""
        return int(self._db(self._scope(table, query)).delete())

    def count(self, table: str, query: Query | None = None) -> int:
        """Count tenant rows matching ``query``."""
        return int(self._db(self._scope(table, query)).count())

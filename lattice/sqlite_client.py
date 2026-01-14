"""
SQLite database client with PostgreSQL-style parameter conversion.
"""

import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


class SQLiteClient:
    """SQLite database client for Lattice."""

    def __init__(self, db_path: str = None):
        """
        Initialize SQLite client.

        Args:
            db_path: Path to SQLite database file.
                     Defaults to LATTICE_DB_PATH env var or 'lattice.db'.
        """
        self.db_path = db_path or os.getenv("LATTICE_DB_PATH", "lattice.db")
        self._ensure_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Get a new database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        # Enable foreign keys
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _ensure_schema(self) -> None:
        """Create database schema if it doesn't exist."""
        schema_path = Path(__file__).parent / "schema.sql"
        if not schema_path.exists():
            return

        with open(schema_path, "r") as f:
            schema_sql = f.read()

        conn = self._get_connection()
        try:
            conn.executescript(schema_sql)
            conn.commit()
        finally:
            conn.close()

    def _convert_params(
        self, query: str, params: Union[Dict, Tuple, List, None]
    ) -> Tuple[str, Tuple]:
        """
        Convert query and params to SQLite format.

        Handles:
        - %(name)s style params -> ? style with tuple
        - %s style params -> ? style
        - Named params dict -> positional tuple
        """
        if params is None:
            return query, ()

        if isinstance(params, dict):
            # Convert %(name)s style to ? style
            # Find all %(name)s patterns and replace in order
            pattern = r"%\((\w+)\)s"
            matches = re.findall(pattern, query)
            if matches:
                converted_query = re.sub(pattern, "?", query)
                converted_params = tuple(params[name] for name in matches)
                return converted_query, converted_params
            else:
                # No named params found, return as-is
                return query, ()
        elif isinstance(params, (list, tuple)):
            # Convert %s style to ? style
            converted_query = query.replace("%s", "?")
            return converted_query, tuple(params)

        return query, ()

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert sqlite3.Row to dict, parsing JSON fields."""
        result = dict(row)
        # Parse JSON fields (stored as TEXT)
        for key, value in result.items():
            if isinstance(value, str) and value.startswith(("{", "[")):
                try:
                    result[key] = json.loads(value)
                except json.JSONDecodeError:
                    pass
        return result

    def execute_single(
        self, query: str, params: Union[Dict, Tuple, List, None] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Execute query and return single row as dict.

        Args:
            query: SQL query
            params: Query parameters (dict or tuple)

        Returns:
            Dict of column->value or None if no results
        """
        converted_query, converted_params = self._convert_params(query, params)
        # Remove FOR UPDATE (not supported in SQLite)
        converted_query = re.sub(r"\s+FOR\s+UPDATE\b", "", converted_query, flags=re.IGNORECASE)

        conn = self._get_connection()
        try:
            cursor = conn.execute(converted_query, converted_params)
            row = cursor.fetchone()
            if row:
                return self._row_to_dict(row)
            return None
        finally:
            conn.close()

    def execute_query(
        self, query: str, params: Union[Dict, Tuple, List, None] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute query and return all rows as list of dicts.

        Args:
            query: SQL query
            params: Query parameters (dict or tuple)

        Returns:
            List of dicts
        """
        converted_query, converted_params = self._convert_params(query, params)
        # Remove FOR UPDATE (not supported in SQLite)
        converted_query = re.sub(r"\s+FOR\s+UPDATE\b", "", converted_query, flags=re.IGNORECASE)

        conn = self._get_connection()
        try:
            cursor = conn.execute(converted_query, converted_params)
            rows = cursor.fetchall()
            return [self._row_to_dict(row) for row in rows]
        finally:
            conn.close()

    def execute_insert(
        self, query: str, params: Union[Dict, Tuple, List, None] = None
    ) -> None:
        """
        Execute insert statement.

        Args:
            query: SQL INSERT query
            params: Query parameters (dict or tuple)
        """
        converted_query, converted_params = self._convert_params(query, params)
        # Remove ::jsonb casts
        converted_query = re.sub(r"::jsonb", "", converted_query)

        conn = self._get_connection()
        try:
            conn.execute(converted_query, converted_params)
            conn.commit()
        finally:
            conn.close()

    def execute_update(
        self, query: str, params: Union[Dict, Tuple, List, None] = None
    ) -> None:
        """
        Execute update statement.

        Args:
            query: SQL UPDATE query
            params: Query parameters (dict or tuple)
        """
        converted_query, converted_params = self._convert_params(query, params)
        # Remove ::jsonb casts
        converted_query = re.sub(r"::jsonb", "", converted_query)

        conn = self._get_connection()
        try:
            conn.execute(converted_query, converted_params)
            conn.commit()
        finally:
            conn.close()

    def execute_delete(
        self, query: str, params: Union[Dict, Tuple, List, None] = None
    ) -> None:
        """
        Execute delete statement.

        Args:
            query: SQL DELETE query
            params: Query parameters (dict or tuple)
        """
        converted_query, converted_params = self._convert_params(query, params)

        conn = self._get_connection()
        try:
            conn.execute(converted_query, converted_params)
            conn.commit()
        finally:
            conn.close()

    def execute_returning(
        self, query: str, params: Union[Dict, Tuple, List, None] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute INSERT/UPDATE/DELETE with RETURNING clause.

        SQLite 3.35+ supports RETURNING. For older versions, we emulate it.

        Args:
            query: SQL query with RETURNING clause
            params: Query parameters (dict or tuple)

        Returns:
            List of dicts containing returned rows
        """
        converted_query, converted_params = self._convert_params(query, params)
        # Remove ::jsonb casts
        converted_query = re.sub(r"::jsonb", "", converted_query)

        conn = self._get_connection()
        try:
            cursor = conn.execute(converted_query, converted_params)
            conn.commit()
            # SQLite 3.35+ supports RETURNING natively
            rows = cursor.fetchall()
            return [self._row_to_dict(row) for row in rows]
        finally:
            conn.close()

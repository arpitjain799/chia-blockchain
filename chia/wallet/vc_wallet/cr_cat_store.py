from __future__ import annotations

from typing import List, Optional

from aiosqlite import Row

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.util.db_wrapper import DBWrapper2
from chia.util.ints import uint64
from chia.wallet.lineage_proof import LineageProof
from chia.wallet.vc_wallet.cr_cat_drivers import CRCAT, ProofsChecker


def _row_to_crcat(row: Row, authorized_providers: List[bytes32], proofs_checker: ProofsChecker) -> CRCAT:
    return CRCAT(
        Coin(bytes32.from_hexstr(row[1]), bytes32.from_hexstr(row[2]), uint64.from_bytes(row[3])),
        bytes32.from_hexstr(row[4]),
        LineageProof.from_bytes(bytes.fromhex(row[5])),
        authorized_providers,
        proofs_checker.as_program(),
        bytes32.from_hexstr(row[6]),
    )


class CRCATStore:
    """
    CRCATStore keeps track of all currently tracked CRCATs
    """

    db_wrapper: DBWrapper2

    @classmethod
    async def create(cls, db_wrapper: DBWrapper2) -> CRCATStore:
        self = cls()

        self.db_wrapper = db_wrapper

        async with self.db_wrapper.writer_maybe_transaction() as conn:
            await conn.execute(
                (
                    "CREATE TABLE IF NOT EXISTS cr_cats("
                    # CRCAT.coin
                    " coin_id text PRIMARY KEY,"
                    " parent_coin_info text,"
                    " puzzle_hash text,"
                    " amount blob,"
                    # CRCAT.tail_hash
                    " tail_hash text,"
                    # CRCAT.lineage_proof
                    " lineage_proof text,"
                    # CRCAT.authorized_providers/proofs_checker are not stored because they are likely very redundant
                    # CRCAT.inner_puzzle_hash
                    " inner_puzhash text)"
                )
            )

            await conn.execute("CREATE INDEX IF NOT EXISTS tail_hash_index ON cr_cats(tail_hash)")

        return self

    async def _clear_database(self) -> None:
        async with self.db_wrapper.writer_maybe_transaction() as conn:
            await (await conn.execute("DELETE FROM vc_records")).close()

    async def add_or_replace_crcat(self, crcat: CRCAT) -> None:
        """
        Store CRCAT in DB.
        """
        async with self.db_wrapper.writer_maybe_transaction() as conn:
            await conn.execute(
                "INSERT or REPLACE INTO cr_cats VALUES(?, ?, ?, ?, ?, ?, ?)",
                (
                    crcat.coin.name().hex(),
                    crcat.coin.parent_coin_info.hex(),
                    crcat.coin.puzzle_hash.hex(),
                    bytes(uint64(crcat.coin.amount)),
                    crcat.tail_hash.hex(),
                    bytes(crcat.lineage_proof).hex(),
                    crcat.inner_puzzle_hash.hex(),
                ),
            )

    async def get_crcat(
        self, coin_id: bytes32, authorized_providers: List[bytes32], proofs_checker: ProofsChecker
    ) -> Optional[CRCAT]:
        """
        Checks DB for CRCAT with specified coin_id and returns it.
        """
        async with self.db_wrapper.reader_no_transaction() as conn:
            cursor = await conn.execute("SELECT * from cr_cats WHERE coin_id=?", (coin_id.hex(),))
            row = await cursor.fetchone()
            await cursor.close()
        if row is not None:
            return _row_to_crcat(row, authorized_providers, proofs_checker)
        return None

    async def get_cr_cats_by_tail_hash(
        self, tail_hash: bytes32, authorized_providers: List[bytes32], proofs_checker: ProofsChecker
    ) -> List[CRCAT]:
        """
        Checks DB for CRCATs with tail_hash and returns them.
        """
        async with self.db_wrapper.reader_no_transaction() as conn:
            cursor = await conn.execute("SELECT * from cr_cats WHERE tail_hash=?", (tail_hash.hex(),))
            rows = await cursor.fetchall()
            await cursor.close()

        return [_row_to_crcat(row, authorized_providers, proofs_checker) for row in rows]

    async def delete_cr_cat(self, coin_id: bytes32) -> None:
        async with self.db_wrapper.writer_maybe_transaction() as conn:
            await (await conn.execute("DELETE FROM cr_cats WHERE coin_id=?", (coin_id.hex(),))).close()

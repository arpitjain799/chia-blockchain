from __future__ import annotations

import json
from typing import Any

import pytest

from chia.rpc.wallet_rpc_api import WalletRpcApi
from chia.simulator.full_node_simulator import FullNodeSimulator
from chia.simulator.time_out_assert import time_out_assert_not_none
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.peer_info import PeerInfo
from chia.util.bech32m import encode_puzzle_hash
from chia.util.ints import uint16, uint64
from chia.wallet.did_wallet.did_wallet import DIDWallet
from chia.wallet.util.address_type import AddressType
from chia.wallet.util.wallet_types import WalletType


@pytest.mark.parametrize(
    "trusted",
    [True, False],
)
@pytest.mark.asyncio
async def test_launch_vc(self_hostname: str, two_wallet_nodes: Any, trusted: Any) -> None:
    num_blocks = 1
    full_nodes, wallets, _ = two_wallet_nodes
    full_node_api: FullNodeSimulator = full_nodes[0]
    full_node_server = full_node_api.server
    wallet_node_0, server_0 = wallets[0]
    wallet_node_1, server_1 = wallets[1]
    wallet_0 = wallet_node_0.wallet_state_manager.main_wallet
    api_0 = WalletRpcApi(wallet_node_0)
    ph = await wallet_0.get_new_puzzlehash()  # noqa: F841

    if trusted:
        wallet_node_0.config["trusted_peers"] = {
            full_node_api.full_node.server.node_id.hex(): full_node_api.full_node.server.node_id.hex()
        }
        wallet_node_1.config["trusted_peers"] = {
            full_node_api.full_node.server.node_id.hex(): full_node_api.full_node.server.node_id.hex()
        }
    else:
        wallet_node_0.config["trusted_peers"] = {}
        wallet_node_1.config["trusted_peers"] = {}

    await server_0.start_client(PeerInfo(self_hostname, uint16(full_node_server._port)), None)
    await server_1.start_client(PeerInfo(self_hostname, uint16(full_node_server._port)), None)
    await full_node_api.farm_blocks_to_wallet(count=num_blocks, wallet=wallet_0)
    did_wallet: DIDWallet = await DIDWallet.create_new_did_wallet(
        wallet_node_0.wallet_state_manager, wallet_0, uint64(1)
    )
    spend_bundle_list = await wallet_node_0.wallet_state_manager.tx_store.get_unconfirmed_for_wallet(did_wallet.id())

    spend_bundle = spend_bundle_list[0].spend_bundle
    assert spend_bundle
    await time_out_assert_not_none(5, full_node_api.full_node.mempool_manager.get_spendbundle, spend_bundle.name())

    await full_node_api.farm_blocks_to_wallet(count=num_blocks, wallet=wallet_0)
    hex_did_id = did_wallet.get_my_DID()
    hmr_did_id = encode_puzzle_hash(bytes32.from_hexstr(hex_did_id), AddressType.DID.hrp(wallet_node_0.config))
    resp = await api_0.vc_mint_vc(dict({"did_id": hmr_did_id}))
    json.dumps(resp)
    await full_node_api.farm_blocks_to_wallet(count=num_blocks, wallet=wallet_0)
    vc_wallet = await wallet_node_0.wallet_state_manager.get_all_wallet_info_entries(wallet_type=WalletType.VC)
    assert len(vc_wallet) == 1
    assert wallet_node_0.wallet_state_manager.vc_store.get_vc_record(resp["vc_record"]["vc"]["launcher_id"]) is not None

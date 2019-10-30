import asyncio
import logging
from typing import List
from blspy import PrivateKey
from src.farmer import Farmer
from src.types.peer_info import PeerInfo
from src.server.server import ChiaServer
from src.protocols.plotter_protocol import PlotterHandshake
from src.server.outbound_message import OutboundMessage, Message, Delivery, NodeType
from src.util.network import parse_host_port

logging.basicConfig(format='Farmer %(name)-25s: %(levelname)-8s %(asctime)s.%(msecs)03d %(message)s',
                    level=logging.INFO,
                    datefmt='%H:%M:%S'
                    )


async def main():
    farmer = Farmer()
    plotter_peer = PeerInfo(farmer.config['plotter_peer']['host'],
                            farmer.config['plotter_peer']['port'],
                            bytes.fromhex(farmer.config['plotter_peer']['node_id']))
    host, port = parse_host_port(farmer)
    server = ChiaServer(port, farmer, NodeType.FARMER)

    _ = await server.start_server(host, NodeType.FULL_NODE, None)

    async def on_connect():
        # Sends a handshake to the plotter
        pool_sks: List[PrivateKey] = [PrivateKey.from_bytes(bytes.fromhex(ce)) for ce in farmer.config["pool_sks"]]
        msg = PlotterHandshake([sk.get_public_key() for sk in pool_sks])
        yield OutboundMessage(NodeType.PLOTTER, Message("plotter_handshake", msg),
                              Delivery.BROADCAST)

    _ = await server.start_client(plotter_peer, NodeType.PLOTTER, on_connect)

    await server.await_closed()

asyncio.run(main())

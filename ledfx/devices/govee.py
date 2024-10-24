import logging
import socket
import struct
import base64
import json
import time
from typing import Optional

import requests
import voluptuous as vol
from requests import ConnectTimeout, ReadTimeout

from ledfx.devices import NetworkedDevice

_LOGGER = logging.getLogger(__name__)



class Govee(NetworkedDevice):
    """
    Support for Govee devices with local API control
    """

    CONFIG_SCHEMA = vol.Schema(
        {
            vol.Required(
                "ip_address",
                description="Hostname or IP address of the device",
            ): str,
            vol.Required(
                "pixel_count",
                description="Number of segments (seen in app)",
                default=1,
            ): vol.All(int, vol.Range(min=1)),
        }
    )

    status: dict[int, tuple[int, int, int]]
    _sock: Optional[socket.socket] = None

    def __init__(self, ledfx, config):
        super().__init__(ledfx, config)
        self._device_type = "Govee"
        self.status = {}
        self.port = 4003  # Control Port
        self.multicast_group = '239.255.255.250'  # Multicast Address
        self.send_response_port = 4001  # Send Scanning
        self.recv_port = 4002  # Responses
        self.udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.udp_server.bind(('', self.recv_port))

    def send_udp(self, message, port=4003):
        data = json.dumps(message).encode('utf-8')
        self.udp_server.sendto(data, (self._config["ip_address"], port))

    # Set Light Brightness
    def set_brightness(self, value):
        self.send_udp({
            "msg": {
                "cmd": "brightness",
                "data": {"value": value}
            }
        })

    def activate(self):
        _LOGGER.info("Activating UDP stream mode...")
        self.send_udp({
            "msg": {
                "cmd": "razer",
                "data": {"pt": "uwABsQEK"}
            }
        })
        time.sleep(.1)
        self.set_brightness(100)
        time.sleep(.1)
        super().activate()

    def deactivate(self):
        _LOGGER.debug("deactivate")
        self.send_udp({
            "msg": {
                "cmd": "razer",
                "data": {"pt": "uwABsQAL"}
            }
        })
        if self._sock is not None:
            self._sock.close()
            self._sock = None

        super().deactivate()

    @staticmethod
    def calculate_xor_checksum(packet):
        checksum = 0
        for byte in packet:
            checksum ^= byte
        return checksum

    def create_dream_view_packet(self, colors):
        header = [0xBB, 0x00, 250, 0xB0, 0x01, len(colors) // 3]
        full_packet = header + colors
        checksum = self.calculate_xor_checksum(full_packet)
        full_packet.append(checksum)
        return full_packet

    def send_encoded_packet(self, packet):
        command = base64.b64encode(bytes(packet)).decode('utf-8')

        self.send_udp({
            "msg": {
                "cmd": "razer",
                "data": {"pt": command}
            }
        })

    def flush(self, data):
        rgb_data = data.flatten().astype(int)
        packet = self.create_dream_view_packet(list(rgb_data))
        self.send_encoded_packet(packet)

    # Get Device Status
    def get_device_status(self):
        self.send_udp({
            "msg": {
                "cmd": "devStatus",
                "data": {}
            }
        })
        self.udp_server.settimeout(1.0)
        try:
            # Receive Response from the device
            response, addr = self.udp_server.recvfrom(1024)
            return f"{response.decode('utf-8')}"

        except socket.timeout:
            return "No response received within the timeout period."


    async def async_initialize(self):
        await super().async_initialize()

        _LOGGER.info("fetching govee's device info...")

        _LOGGER.info(self.get_device_status())

        config = {
            "name": self.config["name"],
            "pixel_count": self.config["pixel_count"],
            "refresh_rate": 42,
        }

        self.update_config(config)



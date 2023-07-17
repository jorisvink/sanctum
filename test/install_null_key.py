import kore
import socket
import struct

class Negotiate:
    def configure(self, args):
        kore.config.workers = 1
        kore.config.deployment = "dev"

        kore.task_create(self.negotiate())

    async def negotiate(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock = kore.socket_wrap(s)

        data = struct.pack("=II32s", 0xdeadbeef, 0xcafebabe, b"\x00" * 32)
        await sock.sendto("/tmp/sanctum-chapel", data)
        kore.shutdown()

koreapp = Negotiate()

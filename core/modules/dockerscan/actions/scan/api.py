import ssl
import socket
import asyncio
import logging
import ipaddress

from typing import Set, Dict

from .model import *

log = logging.getLogger("dockerscan")


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _expand_ips(raw_target: str) -> Set[str]:
    def _expand_ip(ip: str) -> list:
        if "/" in target:
            try:
                return [str(x) for x in ipaddress.ip_network(
                    target,
                    strict=False).hosts()]
            except ValueError:
                # If this error es reach -> target is a domain
                _domain, _subnet, *_ = target.split("/", maxsplit=2)
                new_target = "{}/{}".format(socket.gethostbyname(_domain),
                                            _subnet)

                return [str(x) for x in ipaddress.ip_network(
                    new_target,
                    strict=False).hosts()]
        else:
            try:
                return [str(ipaddress.ip_address(target))]
            except ValueError:
                new_target = socket.gethostbyname(target)

                return [str(x) for x in ipaddress.ip_network(
                    new_target,
                    strict=False).hosts()]

    if "-" in raw_target:
        targets = raw_target.split("-")
    else:
        targets = [raw_target]

    ip_address_expanded = set()

    # Expand IPs
    for target in targets:
        # Extract IP address
            ip_address_expanded.update(_expand_ip(target))

    return ip_address_expanded


def _expand_ports(raw_ports: str) -> Set[int]:

    total_ports = set()

    for port_element in raw_ports.split(","):

        if "-" in port_element:
            _p = port_element.split("-", maxsplit=1)

            if len(_p) == 2 and all(x for x in _p):
                sorted(_p)
                port_start = int(_p[0])
                port_end = int(_p[1])

                ports_ranges = range(port_start, port_end)

            else:

                # If more than 2 elements of less than 1, only get the first
                # port at start port and the end port
                ports_ranges = [_p[0]]

        else:
            ports_ranges = [port_element]

        total_ports.update(ports_ranges)

    return total_ports

# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------
async def _get_connection(target,
                          port,
                          ssl,
                          timeout,
                          loop):
    con = asyncio.open_connection(host=target,
                                  port=port,
                                  ssl=ssl)

    try:
        reader, writer = await asyncio.wait_for(con,
                                                int(timeout),
                                                loop=loop)

        return reader, writer
    except (asyncio.TimeoutError, ConnectionRefusedError):
        # If this is reach -> port closed
        return None, None

async def _check_ports(target: str,
                       port: int,
                       loop: asyncio.AbstractEventLoop,
                       sem: asyncio.BoundedSemaphore,
                       results: list,
                       config: DockerScanModel):

    open_ports = set()

    # for port in ports:

    log.error("   > Trying {}:{}".format(target, port))

    is_ssl = True

    try:
        # If connection SSL?
        try:
            # This definition of ssl context allow to connect with servers with
            # self-signed certs
            sslcontext = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            sslcontext.options |= ssl.OP_NO_SSLv2
            sslcontext.options |= ssl.OP_NO_SSLv3
            sslcontext.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)
            sslcontext.set_default_verify_paths()

            reader, writer = await _get_connection(target,
                                                   port,
                                                   sslcontext,
                                                   config.timeout,
                                                   loop)

            if not reader:
                return

        except ssl.SSLError:
            reader, writer = await _get_connection(target,
                                                   port,
                                                   None,
                                                   config.timeout,
                                                   loop)

            if not reader:
                return

            is_ssl = False

        # Send HTTP Header
        writer.write(
            "GET /v2/ HTTP/1.1\r\nHost: {}\r\n\r\n".format(target).encode()
        )

        # Get Server response
        reader = reader.read(1000)
        try:
            data = await asyncio.wait_for(reader,
                                          1,
                                          loop=loop)
        except (asyncio.TimeoutError, ConnectionRefusedError):
            # If this point reached -> server doesn't sent response
            return

        if b"registry/2.0" in data or \
                        b"Docker-Distribution-Api-Version" in data:

            content = data.lower()

            if b"200 ok" in content:
                status = "open"
            elif b"401" in content:
                status = "auth required"
            else:
                status = "reachable"

            log.info("     + Discovered port {}:{}".format(
                target,
                port
            ))

            open_ports.add((port, status, is_ssl))

        # close descriptor
        writer.close()

        if open_ports:
            results.append(
                {
                    target: open_ports
                }
            )

    finally:
        sem.release()


async def _scan(targets: Set[str],
                ports: Set[int],
                config: DockerScanModel,
                loop: asyncio.AbstractEventLoop):

    max_concurrency = asyncio.BoundedSemaphore(int(config.concurrency),
                                               loop=loop)

    results = []
    tasks = []

    for target in targets:
        for port in ports:
            await max_concurrency.acquire()

            tasks.append(loop.create_task(_check_ports(
                target,
                port,
                loop,
                max_concurrency,
                results,
                config
            )))

    await asyncio.wait(tasks, loop=loop)

    return results


def run_scan_dockerscan(config: DockerScanModel) -> Dict[str, list]:
    assert isinstance(config, DockerScanModel)

    # Expand IPs
    total_ips = _expand_ips(config.target)
    log.critical(" - Total host to analyze: {}".format(len(total_ips)))

    # Expand Ports
    total_ports = _expand_ports(config.ports)
    log.critical(" - Total port per host to check: {}".format(len(total_ports)))

    loop = asyncio.get_event_loop()

    try:
        results = loop.run_until_complete(_scan(total_ips,
                                                total_ports,
                                                config,
                                                loop))

    finally:
        for t in asyncio.Task.all_tasks(loop=loop):
            t.cancel()

        # Ensure all the tasks ends
        async def close_delay_loop():
            loop.stop()

        loop.run_until_complete(asyncio.ensure_future(close_delay_loop()))

    return results


__all__ = ("run_scan_dockerscan",)

import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        bitstring = ''.join(format(byte, '08b') for byte in [*buffer])
        self.version = int(bitstring[0:4], 2)
        self.header_len = 4 * int(bitstring[4:8], 2)
        self.tos = int(bitstring[8:16], 2)
        self.length = int(bitstring[16:32], 2)
        self.id = int(bitstring[32:48], 2)
        self.flags = int(bitstring[48:51], 2)
        self.frag_offset = int(bitstring[51:64], 2)
        self.ttl = int(bitstring[64:72], 2)
        self.proto = int(bitstring[72:80], 2) 
        self.cksum = int(bitstring[80:96], 2)
        self.src = util.inet_ntoa(buffer[12:16])
        self.dst = util.inet_ntoa(buffer[16:20])

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        bitstring = ''.join(format(byte, '08b') for byte in [*buffer])
        self.type = int(bitstring[0:8], 2)
        self.code = int(bitstring[8:16], 2)
        self.cksum = int(bitstring[16:32], 2)

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        bitstring = ''.join(format(byte, '08b') for byte in [*buffer])
        self.src_port = int(bitstring[0:16], 2)
        self.dst_port = int(bitstring[16:32], 2)
        self.len = int(bitstring[32:48], 2)
        self.cksum = int(bitstring[48:64], 2)

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

# TODO feel free to add helper functions if you'd like

def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    # TODO Add your implementation
    discovered_paths = []
    destination_reached = False
    discovered_ips = []
    for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
        if destination_reached:
            break
        sendsock.set_ttl(ttl)
        current_routers = []
        processed_packets = set()

        for attempt in range(PROBE_ATTEMPT_COUNT):
            sendsock.sendto("Potato".encode(), (ip, TRACEROUTE_PORT_NUMBER))

        counter = 0
        while counter != 3:
            counter += 1
            if recvsock.recv_select():
                response, address = recvsock.recvfrom()

                if not is_valid_packet(response):
                    continue

                ip_header_length = (response[0] & 0x0F) * 4
                ip_header = IPv4(response[0:ip_header_length])
                icmp_header = ICMP(response[ip_header_length:ip_header_length + 8])

                if not is_valid_icmp_response(ip_header, icmp_header):
                    continue
                second_ip = IPv4(response[ip_header_length+8:ip_header_length+28])
                if second_ip.dst == ip:
                    if icmp_header.type == 3:
                        current_routers.append(ip_header.src)
                        destination_reached = True
                        break
                    elif icmp_header.type == 11 and icmp_header.code == 0:
                        if ip_header.src not in discovered_ips and ip_header.src not in current_routers:
                            current_routers.append(ip_header.src)
                        if ip_header.src in discovered_ips:
                            counter -= 1
                            processed_packets.add(ip_header.src)
                else:
                    counter -= 1

        if not current_routers:
            current_routers = list(processed_packets)
        discovered_paths.append(current_routers)
        discovered_ips.extend(current_routers)
        util.print_result(current_routers, ttl)

    return discovered_paths

def is_valid_packet(response):
    if len(response) < 28:
        return False
    ip_header_length = (response[0] & 0x0F) * 4
    if len(response) < ip_header_length + 8:
        return False
    return True

def is_valid_icmp_response(ip_header, icmp_header):
    if ip_header.proto != 1:  
        return False
    if icmp_header.type not in [3, 11]: 
        return False
    if icmp_header.type == 11 and icmp_header.code != 0:  
        return False
    return True




if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)

from packets import DNS_Packet

raw_packet = DNS_Packet.build_request(resolve_name="www.northeastern.edu").to_raw_packet()

normal_pack = DNS_Packet.parse(raw_packet)

print(raw_packet)
print(normal_pack)
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(raw_packet, ('208.67.222.222', 53)) # DOES NOT WORK
res = sock.recv(512)
print(res)



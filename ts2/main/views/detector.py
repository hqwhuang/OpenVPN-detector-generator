from scapy.layers.inet import IP, rdpcap, random, sendp
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP,UDP


def judge_valid(opcode):
    if opcode == 5 or opcode == 7 or opcode == 8:
        return 1
    elif opcode > 0 and opcode < 10:
        return 2
    else:
        return 0


def test_type(pkt):
    if pkt.name != 'Ethernet':
        if pkt.name == 'Raw':
            pkt = Ether() / IP(bytes(pkt)[4:])
        else:
            return 0
    if pkt.payload.name != 'IP':
        return 0
    if pkt.payload.payload.name == 'UDP':
        binn = bytes(pkt.payload.payload.payload)
        try:
            c = int(binn.encode('hex'), 16)
        except:
            return 0
        packet_length = pkt.payload.payload.fields['len']
        openvpn_length = packet_length * 8 - 8 * 8
        mask_opcode = 0
        for i in range(5):
            mask_opcode = mask_opcode | (1 << openvpn_length - 1 - i)
        opcode = (c & mask_opcode) >> (openvpn_length - 5)
        if opcode < 1 or opcode > 9:
            return 0
        elif opcode == 5 or opcode == 7 or opcode == 8:
            mask_MPID_array_length = 0
            for i in range(8):
                if openvpn_length - 1 - i - 296 < 0:
                    return 0
                mask_MPID_array_length = mask_MPID_array_length | (1 << openvpn_length - 1 - i - 296)
            MPID_array_length = (c & mask_MPID_array_length) >> (openvpn_length - 296 - 8)
            if opcode == 5:
                if openvpn_length != 304 + MPID_array_length * 4 * 8 + 8 * 8:
                    return 0
                else:
                    return 5
            elif opcode == 7:
                if openvpn_length != 304 + MPID_array_length * 4 * 8 + 4 * 8:
                    return 0
                else:
                    return 7
            else:
                if openvpn_length != 304 + MPID_array_length * 4 * 8 + 12 * 8:
                    return 0
                else:
                    return 8
        else:
            return opcode
    elif pkt.payload.payload.name == 'TCP':
        binn = bytes(pkt.payload.payload.payload)
        try:
            c = int(binn.encode('hex'), 16)
        except:
            return 0
        totalLength = pkt.payload.fields['len']
        ihl = pkt.payload.fields['ihl']
        dataOffset = pkt.payload.payload.fields['dataofs']
        payload_length = (totalLength - (ihl + dataOffset)*4)*8
        mask_openVPN_length = 0
        for i in range(16):
            if payload_length - 1 - i < 0:
                return 0
            mask_openVPN_length = mask_openVPN_length | (1<<payload_length - 1 - i)
        openvpn_length = (c & mask_openVPN_length) >> (payload_length - 16)
        openvpn_length *= 8
        mask_extract = 0
        for i in range(openvpn_length+8*2):
            if payload_length - 1 - i < 0:
                return 0
            mask_extract = mask_extract | (1<<payload_length - 1 - i)
        c = (c & mask_extract) >> (payload_length - (openvpn_length+8*2))
        mask_opcode = 0
        for i in range(5):
            if openvpn_length - 1 - i < 0:
                return 0
            mask_opcode = mask_opcode | (1 << openvpn_length - 1 - i)
        if openvpn_length - 5 <= 0:
            return 0
        opcode = (c & mask_opcode) >> (openvpn_length - 5)
        if opcode < 1 or opcode > 9:
            return 0
        elif opcode == 5 or opcode == 7 or opcode == 8:
            mask_MPID_array_length = 0
            for i in range(8):
                if openvpn_length - 1 - i - 296 < 0:
                    return 0
                mask_MPID_array_length = mask_MPID_array_length | (1 << openvpn_length - 1 - i - 296)
            MPID_array_length = (c & mask_MPID_array_length) >> (openvpn_length - 296 - 8)
            if opcode == 5:
                if openvpn_length != 304 + MPID_array_length * 4 * 8 + 8 * 8:
                    return 0
                else:
                    return 5
            elif opcode == 7:
                if openvpn_length != 304 + MPID_array_length * 4 * 8 + 4 * 8:
                    return 0
                else:
                    return 7
            else:
                if openvpn_length != 304 + MPID_array_length * 4 * 8 + 12 * 8:
                    return 0
                else:
                    return 8
        else:
            return opcode
    else:
        return 0


def packet_generator(srcl = [], dstl = [], layerl = [], num_people = 0):
    if(len(srcl) != num_people or len(dstl) != num_people or len(layerl) != num_people):
        return -1

    p_switcher = {
        '1': 'tcp',
        '0': 'udp',
    }
    pkts = []
    pkt_count = [0] * num_people
    index = []
    for i in range(num_people):
        pkts.append(rdpcap('packets/' + p_switcher[layerl[i]] + str(random.randint(1, 6)) + '.pcap'))
        index.append(i)

    rpkts = []
    for bag in pkts:
        tmp = []
        for pkt in bag:
            tmp.append(pkt)
        rpkts.append(tmp)

    while len(index) > 0:
        ran = random.randint(0, len(index) - 1)
        try:
            if rpkts[index[ran]][pkt_count[index[ran]]][IP].src == '172.20.10.8' or \
                            rpkts[index[ran]][pkt_count[index[ran]]][IP].src == '192.168.1.160':
                rpkts[index[ran]][pkt_count[index[ran]]] = Ether() / IP(src=srcl[index[ran]], dst=dstl[index[ran]]) / \
                                                           rpkts[index[ran]][pkt_count[index[ran]]].payload.payload
            else:
                rpkts[index[ran]][pkt_count[index[ran]]] = Ether() / IP(src=dstl[index[ran]], dst=srcl[index[ran]]) / \
                                                           rpkts[index[ran]][pkt_count[index[ran]]].payload.payload
        except:
            return -1
        sendp(rpkts[index[ran]][pkt_count[index[ran]]])
        pkt_count[index[ran]] += 1
        if pkt_count[index[ran]] >= len(rpkts[index[ran]]):
            index.remove(index[ran])

    return 1
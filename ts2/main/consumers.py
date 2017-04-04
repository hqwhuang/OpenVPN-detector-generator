import re
import json
from channels import Group
from channels.sessions import channel_session
import os
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.layers.inet import TCP,UDP
import socket
from views.detector import judge_valid, test_type, packet_generator

count = 0
meg = 0
running = 0
ratio = 0
num_openVPN = 0
num_suspVPN = 0
step = 0
opcode = [0]*10
pkts = []

def hex_to_raw(data):
    str = ""
    inter = data.split(" ")
    for j in inter:
        for i in range(len(j)):
            if i % 2 == 0:
                str += "\\x"
            str += j[i]
            if i % 2 == 1:
                str += " "
    return str


def write_cap(x):
    global meg
    global count
    global num_openVPN
    global num_suspVPN
    global step
    global opcode
    global pkts

    step -= 1
    count += 1
    judge = test_type(x)
    if judge_valid(judge) == 1:
        num_openVPN += 1
    elif judge_valid(judge) == 2:
        num_suspVPN += 1
    opcode[judge] += 1
    if judge>0:
        if len(pkts) < 1e6:
            pkts.append(x)
    if count > 1e8:
        count /= 1e5
        num_openVPN /= 1e5
        num_suspVPN /= 1e5
        for i in range(len(opcode)):
            opcode[i] /= 1e5
    if step < 0:
        meg.reply_channel.send({'text': json.dumps(count)})
        step = random.randint(30,100)


def stopFilter(x):
    global running

    if running != 1:
        return True
    return False

@channel_session
def ws_connect(message):
    global count
    global meg
    global running
    global num_openVPN
    global num_suspVPN
    global step
    global opcode
    global pkts
    pkts = []
    running = 1
    meg = message
    count = 0
    num_openVPN = 0
    num_suspVPN = 0
    step = 10
    opcode = [0] * 10
    try:
        prefix, dev = message['path'].decode('ascii').strip('/').split('/')
        dev = str(dev)
    except:
        message.reply_channel.send({'text': json.dumps(count)})
        return
    sniff(store=0,iface=dev, prn=write_cap, stop_filter=stopFilter)  # filter="udp"

@channel_session
def ws_receive(message):
    # Look up the room from the channel session, bailing if it doesn't exist
    global running
    global count
    global num_openVPN
    global num_suspVPN
    global opcode
    running = 0

    total = count

    result = dict()
    result['num_openVPN'] = num_openVPN
    result['num_suspVPN'] = num_suspVPN
    result['total'] = total
    for i in range(1,len(opcode)):
        result['opcode%d'%i] = opcode[i]
    if total > 0:
        result['percentage'] = "%.2f" % ((num_openVPN*1.0)/(total*1.0))
        result['percentage_susp'] = "%.2f" % ((num_suspVPN*1.0)/(total*1.0))
    else:
        result['percentage'] = 0
        result['percentage_susp'] = 0

    message.reply_channel.send({'text': json.dumps(result)})


@channel_session
def ws_disconnect(message):
    global pkts
    wrpcap('captured.pcap', pkts)
    return

srcl = []
dstl = []
layerl = []
num_people = 0
@channel_session
def sd_connect(message):
    global srcl
    global dstl
    global layerl
    global num_people
    srcl = []
    dstl = []
    layerl = []
    num_people = 0
    return


@channel_session
def sd_receive(message):
    global srcl
    global dstl
    global layerl
    global num_people
    try:
        data = json.loads(message['text'])
    except ValueError:
        return
    opcode = data['opcode']
    try:
        opcode = int(opcode)
    except:
        message.reply_channel.send({'text': json.dumps("Opcode error!")})
        return
    if opcode == 0:
        dst = data['dst']
        src = data['src']
        layer = data['layer']
        dst = str(dst)
        src = str(src)
        layer = str(layer)
        srcl.append(src)
        dstl.append(dst)
        layerl.append(layer)
        num_people += 1
        result = dict()
        result['opcode'] = 0
        result['dst'] = dst
        result['src'] = src
        if layer == '0':
            result['layer'] = 'UDP'
        else:
            result['layer'] = 'TCP'
        message.reply_channel.send({'text': json.dumps(result)})
    else:
        case = packet_generator(srcl,dstl,layerl,num_people)
        result = dict()
        if case == -1:
            result['opcode'] = '1'
            result['info'] = 'Invalid IP address!'
            message.reply_channel.send({'text': json.dumps(result)})
            return
        else:
            result['opcode'] = '1'
            result['info'] = 'Generated sussessfully!'
            message.reply_channel.send({'text': json.dumps(result)})


@channel_session
def sd_disconnect(message):
    return



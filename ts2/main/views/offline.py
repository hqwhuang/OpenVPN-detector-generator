import os

from django.shortcuts import render_to_response, render, get_object_or_404, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib import auth, messages
from django.template import RequestContext
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from scapy.all import *
import detector as d


def upload_file(request):
    myFile = request.FILES.get("filename", None)
    if not myFile:
        return HttpResponse("No file for upload!")
    file_path = "tmp"

    f = open(file_path, 'w')

    for chunk in myFile.chunks():
        f.write(chunk)
    f.close()
    try:
        cap = rdpcap(file_path)
    except:
        return HttpResponse("File is not supported")
    num_openVpn = 0
    num_suspVpn = 0
    count = 0
    opcode = [0]*10
    for i in cap:
        count+=1
        judge = d.test_type(i)
        if d.judge_valid(judge) == 1:
            num_openVpn += 1
        elif d.judge_valid(judge) == 2:
            num_suspVpn += 1
        opcode[judge] += 1

    if count == 0:
        return HttpResponse("no packet found in the file!")
    percentage = "%.2f" % ((num_openVpn*1.0)/(count*1.0))
    percentage_susp = "%.2f" % ((num_suspVpn*1.0)/(count*1.0))
    chart_true = int(float(percentage) * 100)
    chart_susp = int(float(percentage_susp) * 100)
    chart_false = 100 - chart_true - chart_susp
    opcode1 = opcode[1]
    opcode2 = opcode[2]
    opcode3 = opcode[3]
    opcode4 = opcode[4]
    opcode5 = opcode[5]
    opcode6 = opcode[6]
    opcode7 = opcode[7]
    opcode8 = opcode[8]
    opcode9 = opcode[9]
    return render_to_response('detect_report.html',locals())
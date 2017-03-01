from django.shortcuts import render_to_response, render, get_object_or_404, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib import auth, messages
from django.template import RequestContext
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from random import shuffle, randint
from django.views.generic import TemplateView
import netifaces

def start(request):
    dev = request.GET.get('iface', False)
    return render_to_response('online_detector_start.html', locals())


def finish(request):
    device = netifaces.interfaces()
    num_openVPN = request.GET['num_openVPN']
    total = request.GET['total']
    percentage = request.GET['percentage']
    percentage_susp = request.GET['percentage_susp']
    num_suspVPN = request.GET['num_suspVPN']
    opcode1 = int(request.GET['o1'])
    opcode2 = int(request.GET['o2'])
    opcode3 = int(request.GET['o3'])
    opcode4 = int(request.GET['o4'])
    opcode5 = int(request.GET['o5'])
    opcode6 = int(request.GET['o6'])
    opcode7 = int(request.GET['o7'])
    opcode8 = int(request.GET['o8'])
    opcode9 = int(request.GET['o9'])
    chart_true = int(float(percentage)*100)
    chart_susp = int(float(percentage_susp) * 100)
    chart_false = 100 - chart_true - chart_susp
    return render_to_response('online_detector_finish.html', locals())


def download(request):
    myfile = open('captured.pcap','rb')
    response = HttpResponse(myfile, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename=%s' % 'captured.pcap'
    return response
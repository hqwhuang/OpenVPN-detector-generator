from django.shortcuts import render_to_response, render, get_object_or_404, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib import auth, messages
from django.template import RequestContext
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
import netifaces

def main_page(request):
    return render_to_response('index.html')

def online_detector(request):
    device = netifaces.interfaces()
    return render_to_response('online_detector.html', locals())

def offline_detector(request):
    return render_to_response('offline_detector.html')

def packet_sender(request):
    return render_to_response('packet_sender.html')

def test(request):
    return render_to_response('test.html')
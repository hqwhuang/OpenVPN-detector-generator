from django.shortcuts import render_to_response, render, get_object_or_404, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib import auth, messages
from django.template import RequestContext
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage

def add(request):
    return render_to_response('packet_sender_add.html')
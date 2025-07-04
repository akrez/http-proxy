"""Take incoming HTTP requests and replay them with modified parameters."""
from mitmproxy import ctx
from mitmproxy.net.http.http1.assemble import assemble_request
import requests
from mitmproxy import flow
from mitmproxy import http
from mitmproxy import connection
import time
from mitmproxy.http import HTTPFlow
from mitmproxy import version
from urllib.parse import urlparse
from time import gmtime, strftime
import configparser

def request(flow: HTTPFlow):

    config = configparser.ConfigParser()
    config.read('config.ini')
    new_uri = urlparse(config['agent']['url'])
    new_host_header = config['agent']['host_header']

    new_scheme       = new_uri.scheme
    new_port         = new_uri.port if new_uri.port else 443 if new_scheme == "https" else 80 
    old_host         = flow.request.host
    old_http_version = str(int(float(flow.request.http_version.replace("HTTP/", ""))*10))

    flow.request.path            = new_uri.path + "/" + flow.request.method + "_" +  flow.request.scheme + "_" + old_http_version + "/" + (flow.request.host) + (flow.request.path)
    flow.request.method          = "POST"
    flow.request.http_version    = "HTTP/2.0"
    flow.request.scheme          = new_scheme
    flow.request.host            = new_uri.hostname
    flow.request.port            = new_port
    flow.request.headers["host"] = new_host_header

    print("["+strftime("%H:%M:%S", gmtime()) + "] " + flow.request.http_version.ljust(9, ' ') + flow.request.method.ljust(8, ' ') + old_host)
    # print(assemble_request(flow.request))

def response(flow: http.HTTPFlow):
    # print("["+strftime("%H:%M:%S", gmtime()) + "] " + str(flow.response.status_code) + " " + flow.request.scheme + "://" + (flow.request.host) + (flow.request.path) + "\r\n")
    pass
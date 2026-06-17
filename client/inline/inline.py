from mitmproxy import ctx
from mitmproxy.net.http.http1.assemble import assemble_request
from mitmproxy import flow
from mitmproxy import http
import time
from mitmproxy.http import HTTPFlow
from urllib.parse import urlparse
from time import gmtime, strftime
import configparser
import os
import json
import base64



class Client:
    def __init__(self, host_script_url: str, host_ip: str = ""):
        self.new_uri = urlparse(host_script_url)
        self.host_ip = host_ip if host_ip else None
    def request(self, flow: HTTPFlow):
        new_scheme = self.new_uri.scheme
        new_port = (
            self.new_uri.port
            if self.new_uri.port
            else 443 if new_scheme == "https" else 80
        )
        old_host = flow.request.host
        #
        host_path = flow.request.host + flow.request.path
        b64encoded = base64.b64encode(host_path.encode("utf-8")).decode("utf-8")
        flow.request.path = f"{self.new_uri.path}/{flow.request.method}_{flow.request.scheme}/{b64encoded}"
        flow.request.method = "POST"
        flow.request.scheme = new_scheme
        flow.request.host = self.new_uri.hostname
        flow.request.port = new_port
        flow.request.headers["host"] = self.new_uri.hostname
        #
        print(f"[{strftime('%H:%M:%S', gmtime())}] {flow.request.method.ljust(8, ' ')}{old_host}")
        # print(assemble_request(flow.request))
    def response(self, flow: http.HTTPFlow):
        # print(f"[{strftime('%H:%M:%S', gmtime())}] {flow.response.status_code} {flow.request.scheme}://{flow.request.host}{flow.request.path}\r")
        pass



def read_profiles_json():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "config.json")
    if not os.path.exists(config_path):
        raise FileNotFoundError(
            f"Configuration file '{config_path}' not found"
        )
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"Configuration file '{config_path}' is not valid JSON: {e}"
        )
    profiles = config.get("profiles", {})
    if not isinstance(profiles, dict) or not profiles:
        raise ValueError(f"'profiles' must be a non-empty object in '{config_path}'")
    selected_profile_name = config.get("selected_profile", "")
    if not selected_profile_name:
        raise ValueError("selected_profile is required")
    if selected_profile_name not in profiles:
        available_profiles = ", ".join(f"'{p}'" for p in profiles.keys())
        raise ValueError(
            f"Profile '{selected_profile_name}' not found in '{config_path}'. Available profiles: {available_profiles}"
        )
    profile = profiles[selected_profile_name]
    host_script_url = profile.get("host_script_url", "")
    if not host_script_url:
        raise ValueError("host_script_url is required")
    return {
        "selected_profile_name": selected_profile_name,
        "host_script_url": host_script_url,
        "host_ip": profile.get("host_ip", None)
    }



profile = read_profiles_json()



print(f"selected_profile_name={profile["selected_profile_name"]}\nlocal_server_port={ctx.options.listen_port}\nhost_script_url={profile["host_script_url"]}\nhost_ip={profile["host_ip"]}\n")



ctx.options.connection_strategy = "lazy"
ctx.options.ssl_insecure = True
ctx.options.http2 = False
ctx.options.stream_large_bodies = "128k"



addons = [Client(profile["host_script_url"], profile["host_ip"])]
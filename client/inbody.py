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


selected_profile_name="profile1"


class InlineMode:
    def __init__(self, host_script_url: str, host_header: str = ""):
        self.new_uri = urlparse(host_script_url)
        self.new_host_header = host_header.strip() if host_header else self.new_uri.hostname
    def request(self, flow: HTTPFlow):
        new_scheme = self.new_uri.scheme
        new_port = (
            self.new_uri.port
            if self.new_uri.port
            else 443 if new_scheme == "https" else 80
        )
        old_host = flow.request.host
        new_body = assemble_request(flow.request)
        #
        flow.request.headers.clear()
        #
        flow.request.path = f"{self.new_uri.path}/{flow.request.scheme}"
        flow.request.method = "POST"
        flow.request.scheme = new_scheme
        flow.request.host = self.new_uri.hostname
        flow.request.port = new_port
        flow.request.headers["host"] = self.new_host_header
        flow.request.set_content(new_body)
        #
        print(f"[{strftime('%H:%M:%S', gmtime())}] {flow.request.method.ljust(8, ' ')}{old_host}")
        # print(assemble_request(flow.request))
    def response(self, flow: http.HTTPFlow):
        # print(f"[{strftime('%H:%M:%S', gmtime())}] {flow.response.status_code} {flow.request.scheme}://{flow.request.host}{flow.request.path}\r")
        pass


def read_profiles_ini(selected_profile_name):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    profiles_path = os.path.join(script_dir, "profiles.ini")
    #
    profiles = configparser.ConfigParser()
    if not profiles.read(profiles_path):
        raise FileNotFoundError(
            f"Configuration file '{profiles_path}' not found or cannot be read"
        )
    #
    if not selected_profile_name in profiles:
        available_profiles = ", ".join(f"'{p}'" for p in profiles.sections())
        raise ValueError(
            f"Profile '{selected_profile_name}' not found in '{profiles_path}'. Available profiles: {available_profiles}"
        )
    #
    host_script_url = profiles.get(selected_profile_name, "host_script_url", fallback="")
    if not host_script_url:
        raise ValueError(f"host_script_url is required")

    return {
        "selected_profile_name": selected_profile_name,
        "host_script_url": host_script_url,
        "new_host_header": profiles.get(selected_profile_name, "new_host_header", fallback=urlparse(host_script_url).hostname)
    }

profile= read_profiles_ini(selected_profile_name)

print(f"selected_profile_name={profile["selected_profile_name"]}\nlocal_server_port={ctx.options.listen_port}\nhost_script_url={profile["host_script_url"]}\nnew_host_header={profile["new_host_header"]}\n")


ctx.options.connection_strategy = "lazy"
ctx.options.ssl_insecure = True
ctx.options.stream_large_bodies = "128k"


addons = [InlineMode(profile["host_script_url"], profile["new_host_header"])]

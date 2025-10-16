from mitmproxy import ctx
from mitmproxy.net.http.http1.assemble import assemble_request
from mitmproxy import flow
from mitmproxy import http
import time
from mitmproxy.http import HTTPFlow
from urllib.parse import urlparse
from time import gmtime, strftime
import configparser


class InlineMode:
    def __init__(self, host_script_url: str, host_header: str = ""):
        self.new_uri = urlparse(host_script_url)
        self.new_host_header = host_header.strip() or self.new_uri.hostname

    def request(self, flow: HTTPFlow):
        new_scheme = self.new_uri.scheme
        new_port = (
            self.new_uri.port
            if self.new_uri.port
            else 443 if new_scheme == "https" else 80
        )
        old_host = flow.request.host
        #
        flow.request.path = f"{self.new_uri.path}/{flow.request.method}_{flow.request.scheme}/{flow.request.host}{flow.request.path}"
        flow.request.method = "POST"
        flow.request.scheme = new_scheme
        flow.request.host = self.new_uri.hostname
        flow.request.port = new_port
        flow.request.headers["host"] = self.new_host_header
        #
        print(f"[{strftime('%H:%M:%S', gmtime())}] {flow.request.method.ljust(8, ' ')}{old_host}")
        # print(assemble_request(flow.request))

    def response(self, flow: http.HTTPFlow):
        # print(f"[{strftime('%H:%M:%S', gmtime())}] {flow.response.status_code} {flow.request.scheme}://{flow.request.host}{flow.request.path}\r")
        pass


config = configparser.ConfigParser()
if not config.read("config.ini"):
    raise FileNotFoundError(
        "Configuration file 'config.ini' not found or cannot be read"
    )

local_server_port = int(config.get("config", "local_server_port", fallback=8080))
selected_profile_name = config.get("config", "selected_profile_name", fallback="")

if not selected_profile_name in config:
    available_profiles = ", ".join(f"'{p}'" for p in config.sections())
    raise ValueError(
        f"Profile '{selected_profile_name}' not found in 'config.ini'. Available profiles: {available_profiles}"
    )

if not config.has_option(selected_profile_name, "host_script_url"):
    raise ValueError(
        f"Required option 'host_script_url' not found in profile '{selected_profile_name}'"
    )
host_script_url = config.get(selected_profile_name, "host_script_url", fallback="")

new_host_header = config.get(selected_profile_name, "new_host_header", fallback="")

mode = config.get(selected_profile_name, "mode", fallback="inline")
if mode not in ("inline", "inbody"):
    mode = "inline"

print(f"\n[config]\nselected_profile_name={selected_profile_name}\nlocal_server_port={local_server_port}\n\n[{selected_profile_name}]\nhost_script_url={host_script_url}\nnew_host_header={new_host_header}\nmode={mode}\n")

ctx.options.listen_port = local_server_port
ctx.options.flow_detail = 0
ctx.options.connection_strategy = "lazy"
ctx.options.ssl_insecure = True
ctx.options.stream_large_bodies = "128k"

addons = [InlineMode(host_script_url, new_host_header)]

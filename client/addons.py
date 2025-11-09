from mitmproxy import ctx
from mitmproxy.net.http.http1.assemble import assemble_request
from mitmproxy import flow
from mitmproxy import http
import time
from mitmproxy.http import HTTPFlow
from urllib.parse import urlparse
from time import gmtime, strftime
import configparser


config = {
    # Required
    "selected_profile_name": None,  # e.g., "profile1" Set to None if not using config.ini
    "host_script_url": "",          # e.g., "https://example.com/script.php" Full URL to the remote script
    # Optional
    "local_server_port": 8080,      # default 8080 Port number for the local server
    "new_host_header": None,        # host header value for IP-based. Leave as None for domain-based URLs
    "mode": "inline"                # default "inline" currently only "inline" mode is supported
}


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
        #
        flow.request.path = f"{self.new_uri.path}/{flow.request.method}_{flow.request.scheme}/{flow.request.host}{flow.request.path}"
        flow.request.method = "POST"
        flow.request.scheme = new_scheme
        flow.request.host = self.new_uri.hostname
        flow.request.port = new_port
        flow.request.headers["host"] = self.new_host_header
        #
        # print(f"[{strftime('%H:%M:%S', gmtime())}] {flow.request.method.ljust(8, ' ')}{old_host}")
        # print(assemble_request(flow.request))
    def response(self, flow: http.HTTPFlow):
        # print(f"[{strftime('%H:%M:%S', gmtime())}] {flow.response.status_code} {flow.request.scheme}://{flow.request.host}{flow.request.path}\r")
        pass


def read_config_ini():
    config = configparser.ConfigParser()
    if not config.read("config.ini"):
        raise FileNotFoundError(
            "Configuration file 'config.ini' not found or cannot be read"
        )
    selected_profile_name = config.get("config", "selected_profile_name", fallback="")
    if not selected_profile_name in config:
        available_profiles = ", ".join(f"'{p}'" for p in config.sections())
        raise ValueError(
            f"Profile '{selected_profile_name}' not found in 'config.ini'. Available profiles: {available_profiles}"
        )
    return {
        "selected_profile_name": selected_profile_name,
        "local_server_port": config.get("config", "local_server_port", fallback=""),
        "host_script_url": config.get(selected_profile_name, "host_script_url", fallback=""),
        "new_host_header": config.get(selected_profile_name, "new_host_header", fallback=""),
        "mode": config.get(selected_profile_name, "mode", fallback="")
    }


if not config["selected_profile_name"]:
    config = read_config_ini()


config["local_server_port"] = int(config["local_server_port"] if config["local_server_port"] else 8080)
if not config["host_script_url"]:
    raise ValueError(f"host_script_url is required")
config["mode"] = config["mode"] if config["mode"] in ("inline", "inbody") else "inline"


print(f"\n[config]\nselected_profile_name={config["selected_profile_name"]}\nlocal_server_port={config["local_server_port"]}\n\n[{config["selected_profile_name"]}]\nhost_script_url={config["host_script_url"]}\nnew_host_header={config["new_host_header"]}\nmode={config["mode"]}\n")


ctx.options.listen_port = config["local_server_port"]
ctx.options.connection_strategy = "lazy"
ctx.options.ssl_insecure = True
ctx.options.stream_large_bodies = "128k"


addons = [InlineMode(config["host_script_url"], config["new_host_header"])]

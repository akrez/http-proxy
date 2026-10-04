import io
import json
import os
from http.client import HTTPResponse
from time import gmtime, strftime
from urllib.parse import urlparse

from mitmproxy import ctx
from mitmproxy import http
from mitmproxy.http import HTTPFlow
from mitmproxy.net.http.http1.assemble import assemble_request


class EnvelopeSocket(io.BytesIO):
    def makefile(self, mode, *args, **kwargs):
        return self


def parse_response(raw: bytes):
    first, separator, rest = raw.partition(b"\r\n")
    raw = b"HTTP/1.1 " + first.split(b" ", 1)[1] + separator + rest

    response = HTTPResponse(EnvelopeSocket(raw))
    response.begin()
    headers = [
        (name.encode("latin-1"), value.encode("latin-1"))
        for name, value in response.getheaders()
        if name.lower() not in ("transfer-encoding", "content-length")
    ]
    return response.status, response.reason, headers, response.read()


class Client:
    def __init__(self, host_script_url: str, host_ip: str = ""):
        self.new_uri = urlparse(host_script_url)
        self.host_ip = host_ip if host_ip else None

    def request(self, flow: HTTPFlow):
        new_port = (
            self.new_uri.port
            if self.new_uri.port
            else 443 if self.new_uri.scheme == "https" else 80
        )
        old_host = flow.request.host
        envelope = assemble_request(flow.request)
        #
        flow.request.headers.clear()
        #
        flow.request.path = f"{self.new_uri.path}/{flow.request.scheme}"
        flow.request.method = "POST"
        flow.request.scheme = self.new_uri.scheme
        flow.request.host = self.new_uri.hostname
        flow.request.port = new_port
        flow.request.headers["host"] = self.new_uri.hostname
        flow.request.headers["content-type"] = "application/octet-stream"
        flow.request.set_content(envelope)
        #
        print(f"[{strftime('%H:%M:%S', gmtime())}] {flow.request.method.ljust(8, ' ')}{old_host}")

    def response(self, flow: HTTPFlow):
        if flow.response is None:
            return

        raw = flow.response.content
        if not raw.startswith(b"HTTP/"):
            print(
                f"[envelope] not an envelope: status={flow.response.status_code}"
                f" content-type={flow.response.headers.get('content-type', '')}"
                f" bytes={len(raw)}"
            )
            return

        try:
            status, reason, headers, body = parse_response(raw)
        except Exception as e:
            print(f"[envelope] failed to unpack response: {e}")
            return

        response = http.Response.make(status, body, headers)
        response.reason = reason
        flow.response = response


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
ctx.options.stream_large_bodies = None


addons = [Client(profile["host_script_url"], profile["host_ip"])]

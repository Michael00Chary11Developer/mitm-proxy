from mitmproxy import http

def request(flow: http.HTTPFlow):
    if '.rar' in flow.request.pretty_url:
        # flow.request.headers["Authorization"]="Bearer (token)"
        flow.response=http.Response.make(
            302,
            b"hellow world!",
            {"Location":"https://www.varzesh3.com/"}
        )
from mitmproxy import http
import re

# def request(flow: http.HTTPFlow) -> None:
#     if ".rar" in flow.request.pretty_url:
#         flow.response = http.Response.make(
#             403,
#             b"Forbidden: .rar files are blocked",
#             {"Content-Type": "text/html"}
#         )

# ********************************************************************************************************************
# digiboy filter
# from mitmproxy import http
# def request(flow: http.HTTPFlow) -> None:
#     allowed_domains = ["fdn.digiboy.ir", "digiboy.ir"]
#     if any(domain in flow.request.host for domain in allowed_domains):
#         pretty_url = flow.request.pretty_url
#         blocked_extensions = [".rar", ".exe", ".apk", ".zip", ".tar", ".gz", ".mp3", ".jpg", ".png"]
#     if any(pretty_url.endswith(ext) for ext in blocked_extensions):
#         flow.response = http.Response.make(
#         403,
#     b"Only ISO files are allowed for download from digiboy.ir.",
#     {"Content-Type": "text/plain"}
#     )

# ********************************************************************************************************************
# soft98 filter
# from mitmproxy import http
# import re
# def request(flow: http.HTTPFlow) -> None:
#     allowed_domains = ["soft98.ir", "dl.soft98.ir", "dl2.soft98.ir"]
#     if any(domain in flow.request.host for domain in allowed_domains):
#         pretty_url = flow.request.pretty_url
#         match = re.search(r'.([a-zA-Z0-9]+)(?.*)?$', pretty_url)
#     if match:
#         file_extension = match.group(1).lower()
#         blocked_extensions = ["apk", "rar", "exe", "iso", "mp3", "tar", "gz", "7z", "dmg"]
#     if file_extension in blocked_extensions:
#         flow.response = http.Response.make(
#         403,
#         b"Only ZIP files are allowed for download from soft98.ir and dl.soft98.ir.",
#         {"Content-Type": "text/plain"}
#         )

# ****************************************************************************************************************************
# soft98 , digiboy
# from mitmproxy import http
# import re
# def request(flow: http.HTTPFlow) -> None:
#     digiboy_domains = ["fdn.digiboy.ir", "digiboy.ir", "dl.digiboy.ir"]
#     soft98_domains = ["soft98.ir", "dl.soft98.ir", "dl2.soft98.ir"]
#     if any(domain in flow.request.host for domain in digiboy_domains):
#         pretty_url = flow.request.pretty_url
#         blocked_extensions_digiboy = [".rar", ".exe", ".apk", ".zip", ".tar", ".gz", ".mp3", ".jpg", ".png"]
#     if any(pretty_url.endswith(ext) for ext in blocked_extensions_digiboy):
#         flow.response = http.Response.make(
#         403,
#         b"Only ISO files are allowed for download from digiboy.ir.",
#         {"Content-Type": "text/plain"}
#         )
#     elif any(domain in flow.request.host for domain in soft98_domains):
#         pretty_url = flow.request.pretty_url
#         match = re.search(r'.([a-zA-Z0-9]+)(?.*)?$', pretty_url)
#     if match:
#         file_extension = match.group(1).lower()
#         blocked_extensions_soft98 = ["apk", "rar", "exe", "iso", "mp3", "tar", "gz", "7z", "dmg"]
#     if file_extension in blocked_extensions_soft98:
#         flow.response = http.Response.make(
#         403,
#         b"Only ZIP files are allowed for download from soft98.ir.",
#         {"Content-Type": "text/plain"}
#         )
# ********************************************************************************************************************************
# just soft98 , digiboy

# from mitmproxy import http
# import re

def request(flow: http.HTTPFlow) -> None:

    # allowed_domains = [
    #     "fdn.digiboy.ir", "digiboy.ir", "dl.digiboy.ir",
    #     "soft98.ir", "dl.soft98.ir", "dl2.soft98.ir",
    #     "cdn.ir"
    # ]


    # if not any(domain in flow.request.host for domain in allowed_domains):
    #     flow.response = http.Response.make(
    #         403,
    #         b"Access Forbidden: Only digiboy.ir and soft98.ir are allowed.",
    #         {"Content-Type": "text/plain"}
    #     )
    #     return


    if any(domain in flow.request.host for domain in ["fdn.digiboy.ir", "digiboy.ir", "dl.digiboy.ir"]):
        pretty_url = flow.request.pretty_url


        blocked_extensions_digiboy = [".rar", ".exe", ".apk", ".zip", ".tar", ".gz", ".mp3", ".jpg", ".png"]


        if any(pretty_url.endswith(ext) for ext in blocked_extensions_digiboy):
            flow.response = http.Response.make(
                403,
                b"Only ISO files are allowed for download from digiboy.ir.",
                {"Content-Type": "text/plain"}
            )


    elif any(domain in flow.request.host for domain in ["soft98.ir", "dl.soft98.ir", "dl2.soft98.ir", "dl2soft98.82.ir.cdn.ir"]):
        pretty_url = flow.request.pretty_url


        match = re.search(r'\.([a-zA-Z0-9]+)(\?.*)?$', pretty_url)

        if match:
            file_extension = match.group(1).lower()


            blocked_extensions_soft98 = ["apk", "rar", "exe", "iso", "mp3", "tar", "gz", "7z", "dmg"]


            if file_extension in blocked_extensions_soft98:
                flow.response = http.Response.make(
                    403,
                    b"Only ZIP files are allowed for download from soft98.ir.",
                    {"Content-Type": "text/plain"}
                )

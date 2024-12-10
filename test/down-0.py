import time
from mitmproxy import http, ctx

downloads_in_progress = {}


def request(flow: http.HTTPFlow) -> None:
    # If the request is for a file download, track its progress
    if flow.request.method == "GET" and 'Content-Disposition' in flow.response.headers and "attachment" in flow.response.headers['Content-Disposition']:
        filename = flow.response.headers['Content-Disposition'].split('filename=')[
            1]
        downloads_in_progress[flow.id] = {
            "filename": filename,
            "bytes_downloaded": 0,
            "total_size": int(flow.response.headers.get("Content-Length", 0)),
            "start_time": time.time(),
            "stopped": False
        }


def response(flow: http.HTTPFlow) -> None:
    # If we're tracking a download, start tracking progress
    if flow.id in downloads_in_progress:
        download_info = downloads_in_progress[flow.id]

        # Monitor the download's progress
        if 'Content-Length' in flow.response.headers:
            download_info["total_size"] = int(
                flow.response.headers["Content-Length"])

        if not download_info["stopped"]:
            # Check if the download is still in progress
            content = flow.response.content
            download_info["bytes_downloaded"] += len(content)
            elapsed_time = time.time() - download_info["start_time"]
            progress = (download_info["bytes_downloaded"] /
                        download_info["total_size"]) * 100
            ctx.log.info(
                f"Downloading {download_info['filename']} ({progress:.2f}% complete, {elapsed_time:.2f}s elapsed)")

            # Here you can implement a mechanism to cancel the download if necessary
            # For example, if the user requests a stop:
            if download_info["stopped"]:
                flow.response = http.Response.make(200, b"Download stopped", {
                                                   "Content-Type": "text/plain"})
                ctx.log.info(
                    f"Download of {download_info['filename']} stopped.")
                del downloads_in_progress[flow.id]

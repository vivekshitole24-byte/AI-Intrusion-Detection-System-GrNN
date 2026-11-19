"""Lightweight middleware to catch BrokenPipeError/ConnectionResetError from clients.

When a client disconnects while the server is still sending a response, some servers
raise BrokenPipeError or ConnectionResetError which can spam logs. This middleware
will catch those exceptions, log a short message, and return a safe empty response.

Place early in the MIDDLEWARE list so it wraps view execution and streaming responses.
"""
from __future__ import annotations

import logging

from django.http import HttpResponse, StreamingHttpResponse

logger = logging.getLogger("django.request")


class BrokenPipeMiddleware:
    """Catch client disconnect errors and log them concisely."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            response = self.get_response(request)
            return response
        except (BrokenPipeError, ConnectionResetError) as exc:
            client = request.META.get("REMOTE_ADDR") or "unknown"
            logger.warning("Broken pipe / connection reset from %s: %s", client, exc)
            return HttpResponse(status=204)


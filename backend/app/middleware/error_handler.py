from __future__ import annotations

import logging

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

FRIENDLY_ERRORS = {
    400: "Something went wrong with your request. Please check your input and try again.",
    401: "You need to sign in to access this. Please log in and try again.",
    403: "You don't have permission to do this. If you think this is a mistake, contact support.",
    404: "We couldn't find what you're looking for. It may have been moved or deleted.",
    409: "This already exists. Try a different value.",
    413: "The file you uploaded is too large. Maximum size is 10MB.",
    415: "This file type is not supported. Please upload a text, CSV, or document file.",
    422: "Some information you provided is invalid. Please check your input and try again.",
    429: "You've reached your scan limit for this month. Upgrade your plan for more scans.",
    500: "Something went wrong on our end. We've been notified and are looking into it.",
    502: "We're having trouble connecting to a service. Please try again in a moment.",
    503: "MyCyber is temporarily unavailable. Please try again shortly.",
}


async def http_exception_handler(
    request: Request,
    exc: HTTPException,
) -> JSONResponse:
    """
    Returns human-readable error messages.
    Preserves structured error detail for
    billing/limit errors (they have dict detail).
    Logs all 5xx errors with request info.
    """
    if exc.status_code >= 500:
        logger.error(
            f"Server error {exc.status_code}: "
            f"{exc.detail} on {request.url.path}"
        )

    if isinstance(exc.detail, dict):
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.detail,
        )

    friendly = FRIENDLY_ERRORS.get(
        exc.status_code,
        str(exc.detail),
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": friendly,
            "code": exc.status_code,
        },
    )


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """
    Converts Pydantic validation errors into
    human-readable field-specific messages.
    """
    _ = request

    errors = []
    for error in exc.errors():
        field = " -> ".join(str(e) for e in error["loc"] if e != "body")
        msg = error["msg"]

        if "string_too_long" in msg or "max_length" in msg:
            friendly_msg = f"{field} is too long."
        elif "string_too_short" in msg or "min_length" in msg:
            friendly_msg = f"{field} is too short."
        elif "value_error.email" in msg or "email" in msg:
            friendly_msg = "Please enter a valid email address."
        elif "value_error.missing" in msg or "missing" in msg:
            friendly_msg = f"{field} is required."
        elif "pattern" in msg:
            friendly_msg = f"{field} format is invalid."
        else:
            friendly_msg = f"{field}: {msg}"

        errors.append(friendly_msg)

    return JSONResponse(
        status_code=422,
        content={
            "error": True,
            "message": "Please fix the following: " + " | ".join(errors),
            "fields": errors,
            "code": 422,
        },
    )

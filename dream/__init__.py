# -*- coding: utf-8 -*-
#
# © 2010, 2011 SimpleGeo, Inc. All rights reserved.
# Author: Ian Eure <ian@simplegeo.com>
#

"""The core of the CN (Places) API."""

from functools import wraps
from itertools import chain

import sys
import decoroute
import logging
import json

from webob import Request, Response, exc


_RESP_LEVELS = {100: logging.INFO,
                200: logging.INFO,
                300: logging.INFO,
                400: logging.WARN,
                500: logging.ERROR}


class JSONResponse(Response):

    """A response in JSON format."""

    default_content_type = 'application/json'

    def __init__(self, **kwargs):
        kwargs.update(body=json.dumps(kwargs['body']))
        Response.__init__(self, **kwargs)


class HumanReadableJSONResponse(Response):

    """A response in JSON format, with formatting for human readability"""

    default_content_type = 'application/json'

    def __init__(self, **kwargs):
        kwargs.update(body=json.dumps(kwargs['body'], indent=4))
        Response.__init__(self, **kwargs)


def _wrap_endpoint(function):
    """Wrap an endpoint, creating a Request object from the WSGI env."""
    @wraps(function)
    def wrapper(env, *args, **kwargs):
        try:
            return function(Request(env), *args, **kwargs)
        except Exception, ex:
            return ex

    return wrapper


class App(decoroute.App):

    """API Core dispatcher."""

    logs = {}

    def __init__(self, prefix="", key="dream.app"):
        decoroute.App.__init__(self, prefix, key)
        self.map = dict(
            ((method, decoroute.UrlMap())
             for method in ('HEAD', 'GET', 'POST', 'PUT', 'DELETE')))
        self.not_found(lambda e: exc.HTTPNotFound(detail="Not found"))
        self._render = self._render_response
        self.logs['access'] = logging.getLogger('dream.access')
        self.logs['error'] = logging.getLogger('dream.error')

    def route(self, env):
        """Route a request.

        Checks the method-specific map first, then the global as a fallback.
        """
        env[self._key] = self
        path, n = self._prefix[1].subn('', env['PATH_INFO'])
        if n != 1:
            raise exc.HTTPNotFound()

        try:
            endpoint, kw = self.map[env['REQUEST_METHOD']].route(path)
        except decoroute.NotFound, nf:
            raise (exc.HTTPNotFound(" ".join(nf.args)), None,
                   getattr(sys, 'last_traceback', None))
        return endpoint(env, **kw)

    def expose(self, pattern, method="GET", **kw):
        """Register a URL pattern for a specific HTTP method."""
        if method not in self.map:
            raise Exception("No such method: %s" % method)

        def decorate(f):
            self.map[method].add(pattern, _wrap_endpoint(f), **kw)
            return f
        return decorate

    def _log_response(self, env, resp):
        """Log this response in the access log."""
        self.logs['access'].log(
            _RESP_LEVELS.get(resp.status_int - (resp.status_int % 100),
                             logging.ERROR),
            "%s %d %s %s?%s", env.get('HTTP_X_SIMPLEGEO_USER', "anon"),
            resp.status_int, env.get('REQUEST_METHOD', "?GET?"),
            env.get('PATH_INFO', '/???'), env.get('QUERY_STRING', " ?QS?"))

    def _render_response(self, env, resp):
        """Render the Response object into WSGI format."""

        if isinstance(resp, Exception):
            self.logs['error'].exception(resp)

        if isinstance(resp, exc.HTTPException):
            resp = resp.json_response()

        if isinstance(resp, Exception):
            resp = exc.HTTPInternalServerError.from_exception(resp).json_response()

        if not isinstance(resp, Response):
            resp = exc.HTTPInternalServerError(
                detail=json.dumps(
                    {'error': "Expected a Response object, got %s instead." %
                     str(type(resp))})).json_response()

        self._log_response(env, resp)
        return (resp.status, resp.headers.items(), resp.app_iter)

    def endpoints(self):
        """Return a dict of registered endpoints."""
        return dict(
            chain.from_iterable(
                (('%s %s' % (meth, pattern), func.__doc__ or "Undocumented.")
                 for ((func, _), pattern) in
                 self.map[meth]._endpoints.iteritems())
                for meth in self.map.iterkeys()))


class HTTPExceptionMixin(object):

    def json_response(self):
        """Return a Response object from this Exception."""
        return JSONResponse(
            body={'detail': self.detail, 'comment': self.comment},
            status=self.status)

    @classmethod
    def from_exception(cls, ex):
        """Return a new HTTPException from a non-HTTPException."""
        return cls(detail="Caught exception %s: %s" % (
                type(ex), str(ex)))


def endpoints(app, *args, **kwargs):
    """Create an endpoint which introspects endpoints of an app."""

    @app.expose(*args, **kwargs)
    def __endpoints__(request):
        """Returns known endpoints and their docstrings."""
        return HumanReadableJSONResponse(body=app.endpoints())


exc.WSGIHTTPException.__bases__ += (HTTPExceptionMixin,)
#decoroute.NotFound = exc.HTTPNotFound

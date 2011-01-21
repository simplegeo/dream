# -*- coding: utf-8 -*-
#
# © 2010, 2011 SimpleGeo, Inc. All rights reserved.
# Author: Ian Eure <ian@simplegeo.com>
#

"""Dream, a hyperminimal WSGI framework."""

import sys
import logging
import json
from uuid import uuid1
from functools import wraps
from itertools import chain
from traceback import format_exc

import decoroute
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
        Response.__init__(self, body=self.serialize(kwargs.pop('body')),
                          **kwargs)

    def serialize(self, obj):
        """Return this object as a JSON string."""
        return json.dumps(obj)


class HumanReadableJSONResponse(JSONResponse):

    """A response in JSON format, with formatting for human readability"""

    def serialize(self, obj):
        return json.dumps(obj, indent=4)


class App(decoroute.App):

    """API Core dispatcher."""

    logs = {}
    debug = False

    def __init__(self, prefix="", key="dream.app", debug=False):
        decoroute.App.__init__(self, prefix, key)
        self.map = dict(
            ((method, decoroute.UrlMap())
             for method in ('HEAD', 'GET', 'POST', 'PUT', 'DELETE')))
        self.not_found(lambda e: exc.HTTPNotFound(detail="Not found"))
        self._render = self._render_response
        self.debug = debug
        self.logs['access'] = logging.getLogger('dream.access')
        self.logs['error'] = logging.getLogger('dream.error')

    def route(self, env):
        """Route a request.

        Checks the method-specific map first, then the global as a fallback.
        """
        env[self._key] = self
        path, num = self._prefix[1].subn('', env['PATH_INFO'])
        if num != 1:
            raise exc.HTTPNotFound()

        try:
            endpoint, kwargs = self.map[env['REQUEST_METHOD']].route(path)
            return endpoint(Request(env, charset='utf-8'), **kwargs)

        except decoroute.NotFound, nfex:
            raise exc.HTTPNotFound(" ".join(nfex.args)), None, \
                getattr(sys, 'last_traceback', None)

        except Exception, ex:
            return ex

    def expose(self, pattern, method="GET", function=None, **kwargs):
        """Register a URL pattern for a specific HTTP method."""
        if method not in self.map:
            raise Exception("No such method: %s" % method)

        def decorate(function):
            """Add this function to the method map."""
            self.map[method].add(pattern, function, **kwargs)
            return function
        return decorate

    def _log_response(self, env, resp):
        """Log this response in the access log."""
        self.logs['access'].log(
            _RESP_LEVELS.get(resp.status_int - (resp.status_int % 100),
                             logging.ERROR),
            "%s %d %s %s?%s", env.get('HTTP_X_SIMPLEGEO_USER', "anon"),
            resp.status_int, env.get('REQUEST_METHOD', "?GET?"),
            env.get('PATH_INFO', '/???'), env.get('QUERY_STRING', " ?QS?"))

    def _mangle_response(self, resp):
        """Mangle the response, if warranted."""
        if not isinstance(resp, Response) and not isinstance(resp, Exception):
            resp = Exception("Expected a Response object, got %s instead." %
                             str(type(resp)))

        if isinstance(resp, Exception):
            error_cookie = uuid1().hex
            self.logs['error'].exception(
                "Cookie %s: " +
                "; ".join(line.strip()
                          for line in format_exc().strip().split("\n")[-3:]),
                error_cookie)
            func = (_debug_exception_to_reponse if self.debug
                    else _exception_to_response)
            resp = func(resp, error_cookie)

        return resp

    def _render_response(self, env, resp):
        """Render the Response object into WSGI format."""

        resp = self._mangle_response(resp)
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


def _debug_exception_to_reponse(exception, cookie=None):
    """Return a JSONResponse representing an uncaught Exception.

    This includes detailed information for debugging, and should not
    be used in production to avoid information leaks.
    """
    return JSONResponse(status=getattr(exception, 'status', 500),
                        body={'detail': "Caught exception %s: %s" % (
                type(exception), str(exception)),
                              'traceback': format_exc(),
                              'cookie': cookie})


def _exception_to_response(exception, cookie=None):
    """Return a JSONResponse representing an uncaught Exception.

    This doesn't include any debug information, and is suitable for
    the general public to consume.
    """
    return JSONResponse(
        body={'detail': str(exception)
              if isinstance(exception, exc.HTTPException) else
              "An internal error occured. "
              "If it makes you feel better, have a cookie.",
              'cookie': cookie},
        status=getattr(exception, 'status', 500))


def endpoints(app, *args, **kwargs):
    """Create an endpoint which introspects endpoints of an app."""

    @app.expose(*args, **kwargs)
    def __endpoints__(request):
        """Returns known endpoints and their docstrings."""
        return HumanReadableJSONResponse(body=app.endpoints())

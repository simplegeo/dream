# -*- coding: utf-8 -*-
#
# © 2010, 2011 SimpleGeo, Inc. All rights reserved.
# Author: Ian Eure <ian@simplegeo.com>
#

"""Dream, a hyperminimal WSGI framework."""

import os
import sys
import logging
import json
import threading
from uuid import uuid1
from functools import wraps
from itertools import chain
from traceback import format_list, extract_stack, extract_tb

import decoroute
from webob import Request as WebObRequest, Response, exc
from webob.request import NoDefault


_RESP_LEVELS = {100: logging.INFO,
                200: logging.INFO,
                300: logging.INFO,
                400: logging.WARN,
                500: logging.ERROR}


class Request(WebObRequest):

    """Dream request object."""

    def __init__(self, environ, charset=NoDefault,
                 unicode_errors=NoDefault,
                 decode_param_names=NoDefault, **kw):
        self._id = None
        WebObRequest.__init__(
            self, environ, charset=charset, unicode_errors=unicode_errors,
            decode_param_names=decode_param_names, **kw)

    def _id__get(self):
        if not self._id:
            self._id = uuid1().hex

        return self._id

    def _id__set(self, value):
        self._id = value

    id = property(_id__get, _id__set)


class JSONResponse(Response):

    """A response in JSON format."""

    default_content_type = 'application/json'

    def __init__(self, **kwargs):
        Response.__init__(self, body=self.serialize(kwargs.pop('body', None)),
                          **kwargs)

    def serialize(self, obj):
        """Return this object as a JSON string."""
        if obj is None:
            return ""
        return json.dumps(obj)


class HumanReadableJSONResponse(JSONResponse):

    """A response in JSON format, with formatting for human readability"""

    def serialize(self, obj):
        if obj is None:
            return ""
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

    def make_request(self, env, **kwargs):
        """Return a new Request object for this env."""
        return Request(env, **kwargs)

    def route(self, env):
        """Route a request.

        Checks the method-specific map first, then the global as a fallback.
        """

        request = self.make_request(env, charset='utf-8')

        try:
            env[self._key] = self
            path, num = self._prefix[1].subn('', env['PATH_INFO'])
            if num != 1:
                raise exc.HTTPNotFound()

            endpoint, kwargs = self.map[env['REQUEST_METHOD']].route(path)
            return (request, endpoint(request, **kwargs))

        except decoroute.NotFound, nfex:
            new_ex = exc.HTTPNotFound(" ".join(nfex.args))
            if not hasattr(new_ex, '__traceback__'):
                new_ex.__traceback__ = sys.exc_info()[-1]
            return (request, new_ex)

        except Exception, ex:
            if not hasattr(ex, '__traceback__'):
                ex.__traceback__ = sys.exc_info()[-1]
            return (request, ex)

    def expose(self, pattern, method="GET", function=None, **kwargs):
        """Register a URL pattern for a specific HTTP method."""
        if method not in self.map:
            raise Exception("No such method: %s" % method)

        def decorate(function):
            """Add this function to the method map."""
            self.map[method].add(pattern, function, **kwargs)
            return function

        return decorate(function) if function else decorate

    def _log_response(self, req, resp):
        """Log this response in the access log."""
        self.logs['access'].log(
            _RESP_LEVELS.get(resp.status_int - (resp.status_int % 100),
                             logging.ERROR),
            "%d %s %s", resp.status_int, req.method, req.url)

    def format_traceback(self, resp):
        """Return a formatted traceback, suitable for logging.

        If you prefer multi-line style, you can override this with:
        return "\n".join(_format_traceback(resp))
        """
        return ';'.join(line.strip().replace("\n", ':') for line in
                        _format_traceback(resp))

    def _mangle_response(self, req, resp):
        """Mangle the response, if warranted."""
        if (isinstance(resp, Response)
            and not isinstance(resp, (exc.HTTPClientError,
                                      exc.HTTPServerError))):
            return resp

        if not isinstance(resp, Exception):
            resp = Exception("Expected a Response object, got %s instead." %
                             str(type(resp)))
            resp.__traceback__ = extract_stack()

        func = (_debug_exception_to_reponse if self.debug
                else _exception_to_response)
        return func(req, resp)

    def _get_error_logger(self, env):
        """Return an error logger for this request."""
        if env.get('wsgi.multiprocess', False):
             name = 'dream.error.%d' % os.getpid()
        elif env.get('wsgi.multithread', False):
            name = 'dream.error.%s' % threading.currentThread().getName()
        else:
            name = 'dream.error'

        log = logging.getLogger(name)
        if not log.handlers:
            log.addHandler(logging.StreamHandler(env.get('wsgi.errors',
                                                         sys.stderr)))
        return log

    def _render_response(self, env, (request, in_resp)):
        """Render the Response object into WSGI format."""

        resp = self._mangle_response(request, in_resp)
        if isinstance(resp, (exc.HTTPClientError, exc.HTTPServerError)):
            self._get_error_logger(env).error(
                "Request-Id %s: %s %s", request.id, repr(in_resp),
                self.format_traceback(in_resp))

        self._log_response(request, resp)
        return (resp.status, resp.headers.items(), resp.app_iter)

    def endpoints(self):
        """Return a dict of registered endpoints."""
        return dict(
            chain.from_iterable(
                (('%s %s%s' % (meth, self._prefix[0], pattern),
                  func.__doc__ or "Undocumented.")
                 for ((func, _), pattern) in
                 self.map[meth]._endpoints.iteritems()
                 if not getattr(func, '__hidden__', False))
                for meth in self.map.iterkeys()))


def _format_traceback(exc_):
    """Return a formatted traceback as a list."""
    if not hasattr(exc_, '__traceback__'):
        return ["No traceback available"]

    return format_list(
        exc_.__traceback__ if isinstance(exc_.__traceback__, list) else
        extract_tb(exc_.__traceback__))


def _debug_exception_to_reponse(request, exception):
    """Return a JSONResponse representing an uncaught Exception.

    This includes detailed information for debugging, and should not
    be used in production to avoid information leaks.
    """
    return JSONResponse(
        status=getattr(exception, 'status', 500),
        body={'detail': "Caught exception %s: %s" % (
                type(exception), str(exception)),
              'traceback': _format_traceback(exception),
              'request_id': request.id})


def _exception_to_response(request, exception):
    """Return a JSONResponse representing an uncaught Exception.

    This doesn't include any debug information, and is suitable for
    the general public to consume.
    """
    return JSONResponse(
        body={'detail': (exception.detail or exception.explanation)
              if isinstance(exception, exc.HTTPException) else
              "An internal error occured.",
              'request_id': request.id},
        status=getattr(exception, 'status', 500))


def endpoints(app, *args, **kwargs):
    """Create an endpoint which introspects endpoints of an app."""

    @app.expose(*args, **kwargs)
    def __endpoints__(request):
        """Returns known endpoints and their docstrings."""
        return HumanReadableJSONResponse(body=app.endpoints())


def hidden(function):
    """Mark an endpoint hidden."""

    function.__hidden__ = True
    return function

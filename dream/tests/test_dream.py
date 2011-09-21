# -*- coding: utf-8 -*-
#
# © 2010, 2011 SimpleGeo, Inc. All rights reserved.
# Author: Ian Eure <ian@simplegeo.com>
#

"""Tests for Dream."""

import sys
import unittest
import traceback
import json

from webob.multidict import UnicodeMultiDict
from dream import (App, Request, Response, JSONResponse,
                   HumanReadableJSONResponse, exc,
                   endpoints, hidden, _exception_to_response,
                   _debug_exception_to_reponse, _format_traceback)


def _env(**kwargs):
    """Return a stub WSGI environment."""
    return dict({'wsgi.url_scheme': 'http',
                 'SERVER_NAME': 'localhost',
                 'SERVER_PORT': 80,
                 'SERVER_PROTOCOL': 'HTTP/1.1',
                 'REQUEST_METHOD': 'GET',
                 'PATH_INFO': '/'
                 }, **kwargs)


class JSONResponseTest(unittest.TestCase):

    """Test the JSONResponse."""

    def setUp(self):
        self.resp_class = JSONResponse

    def test_content_type(self):
        """Make sure a content-type is set."""
        body = {'foo': 'bar'}
        resp = self.resp_class(body=body)
        self.assert_(
            resp.content_type.startswith('application/json'))

    def test_body(self):
        """Make sure a content-type is set."""
        body = {'foo': 'bar'}
        resp = self.resp_class(body=body)
        self.assert_(json.loads(resp.body) == body)

    def test_no_body(self):
        """Make sure JSONResponses with no body work."""
        resp = self.resp_class(status=304)
        self.assertEqual(resp.body, "")


class HumanReadableJSONResponseTest(JSONResponseTest):

    def setUp(self):
        self.resp_class = HumanReadableJSONResponse


class TestExpose(unittest.TestCase):

    """Test App.expose."""

    def setUp(self):
        self.app = App()

    def test_expose_method(self):
        """Make sure the original method is preserved."""
        f = lambda request: None
        f_ = self.app.expose('/test_expose')(f)
        self.assert_(f_ is f)

    def test_expose_methods(self):
        """Make sure invalid methods raise an exception."""
        self.assertRaises(Exception, self.app.expose, '/foo', 'CHEESE')

    def test_expose_method_maps(self):
        """Make sure patterns are added to the correct maps."""
        url, method = ('/cheese', 'GET')
        old_len = len(self.app.map[method]._patterns)
        f = lambda request: None
        self.app.expose(url, method)(f)
        self.assert_(len(self.app.map[method]._patterns) > old_len)
        self.assert_(url in self.app.map[method]._patterns)
        self.assert_(self.app.map[method]._patterns[url][1] is f)

    def test_expose_method_decorates(self):
        """Make sure functions aren't decorated when added."""
        url, method = ('/shop', 'GET')
        old_len = len(self.app.map[method]._patterns)
        f = lambda request: None
        self.app.expose(url, method)(f)
        self.assert_(self.app.map[method]._patterns[url][1] is f)


class RenderTest(unittest.TestCase):

    def setUp(self):
        self.app = App()

    def test_httpexception(self):
        ex = exc.HTTPNotFound(detail="test")
        out = self.app._render({}, (Request(_env()), ex))
        self.assertTrue(out[0].startswith('404'))

    def test_non_httpexception(self):
        ex = ValueError("WTF")
        out = self.app._render({}, (Request(_env()), ex))
        self.assertTrue(out[0].startswith("500"))

    def test_json_type(self):
        ex = ValueError("WTF")
        out = self.app._render({}, (Request(_env()), ex))
        headers = dict(out[1])
        self.assertTrue('Content-Type' in headers)
        self.assertEqual(headers['Content-Type'], 'application/json')

    def test_bad_response(self):
        resp = self.app._render({}, (Request(_env()), "foo"))
        self.assertTrue(isinstance(resp, tuple))
        self.assertTrue(resp[0].startswith("500"))

    def test_bad_request(self):
        message = "You dun goof'd"
        ex = exc.HTTPBadRequest(message)
        (response, headers, body) = self.app._render({}, (Request(_env()), ex))
        body = "".join(body)
        self.assertTrue(len(body) > 0)
        blab = json.loads(body)
        self.assertEqual(blab['detail'], message)


class GetEndpointsTest(unittest.TestCase):

    """Test _get_endpoints."""

    def setUp(self):
        self.app = App()

    def test_endpoints(self):
        self.app.expose('foo')(lambda request: Response())
        self.app.expose('bar')(lambda request: Response())

        endpoints = self.app.endpoints()
        self.assertTrue('GET foo' in endpoints.keys())
        self.assertTrue('GET bar' in endpoints.keys())


class EndpointsTest(unittest.TestCase):

    """Test dream.endpoints()"""

    def setUp(self):
        self.app = App()
        endpoints(self.app, '/endpoints')

    def test_endpoints(self):
        self.assertTrue('GET /endpoints' in self.app.endpoints().keys())

    def test_endpoints_reponse(self):
        (request, response) = self.app.route({'REQUEST_METHOD': 'GET',
                                              'PATH_INFO': '/endpoints'})
        self.assertTrue(isinstance(response, HumanReadableJSONResponse))

    def test_has_prefix(self):
        """Make sure endpoint URLs include the prefix."""
        prefix = "/foo"
        app = App(prefix=prefix)
        endpoints(app, "/endpoints")
        for endpoint in app.endpoints().iterkeys():
            self.assertTrue(prefix in endpoint)


class RouteTest(unittest.TestCase):

    """Test App.route()."""

    def test_prefix_404(self):
        app = App(prefix='/1.0')
        self.assertTrue(isinstance(
                app.route({'REQUEST_METHOD': 'GET', 'PATH_INFO': '/foo'})[1],
                exc.HTTPNotFound))

    def test_nonprefix_404(self):
        app = App()
        (req, resp) = app.route({'REQUEST_METHOD': 'GET', 'PATH_INFO': '/foo'})
        self.assertTrue(isinstance(resp, exc.HTTPNotFound))

    def test_success(self):
        response = Response(body="Hi")
        app = App()
        app.expose('/')(lambda request: response)
        (req, resp) = app.route({'REQUEST_METHOD': 'GET', 'PATH_INFO': '/'})
        self.assertTrue(resp is response)

    def test_generates_request(self):
        """Make sure request objects are generated."""
        runs = []
        app = App()

        @app.expose("/foo")
        def test_f(request):
            runs.append(True)
            self.assert_(isinstance(request, Request))
            return Response()

        (req, resp) = app.route({'REQUEST_METHOD': 'GET', 'PATH_INFO': "/foo"})
        self.assert_(len(runs) == 1)

    def test_http_exceptions_returned(self):
        """Make sure HTTPExceptions are returned."""
        ex = exc.HTTPException(000, "Test exception")
        app = App()

        @app.expose("/foo")
        def test_f(request):
            raise ex

        (req, resp) = app.route({'REQUEST_METHOD': 'GET',
                            'PATH_INFO': "/foo"})
        self.assert_(resp is ex)

    def test_exceptions_returned(self):
        """Make sure non-HTTPExceptions are returned."""
        ex = Exception("Test exception")
        app = App()

        @app.expose("/foo")
        def test_f(request):
            raise ex

        (req, resp) = app.route({'REQUEST_METHOD': 'GET',
                            'PATH_INFO': "/foo"})
        self.assert_(resp is ex)

    def test_unicode_request(self):
        """Make sure the request uses Unicode."""
        env = {'QUERY_STRING': 'q=ü'}
        app = App()

        @app.expose("/foo")
        def __endpoint__(request):
            self.assertTrue(isinstance(request.GET, webob.UnicodeMultiDict))

        app.route({'REQUEST_METHOD': 'GET',
                   'PATH_INFO': "/foo"})


class ExceptionToResponseTest(unittest.TestCase):

    def setUp(self):
        self.func = _exception_to_response

    def test_types(self):
        resp = self.func(Request(_env()), Exception("foo"))
        self.assertTrue(isinstance(resp, Response))

    def test_status(self):
        """Make sure webob exception statuses are preserved."""
        not_found = exc.HTTPNotFound("Sorry")
        resp = self.func(Request(_env()), not_found)
        self.assertEqual(not_found.status, resp.status)

    def test_has_detail(self):
        """Make sure there's error detail."""
        resp = self.func(Request(_env()), Exception("foo"))
        body = json.loads(resp.body)
        self.assertTrue('detail' in body)

    def test_has_cookie(self):
        """Make sure the cookie is included."""
        req = Request(_env())
        resp = self.func(req, Exception("foo"))
        body = json.loads(resp.body)
        self.assertTrue('request_id' in body)
        self.assertEqual(body['request_id'], req.id)

    def test_no_traceback(self):
        """Make sure there is no traceback."""
        resp = self.func(Request(_env()), Exception("foo"))
        self.assertFalse('traceback' in json.loads(resp.body))

    def test_httpexception_message(self):
        """Make sure the message from a HTTPException is preserved."""
        msg = "foo"
        resp = self.func(Request(_env()), exc.HTTPBadRequest(msg))
        self.assertEqual(json.loads(resp.body)['detail'], msg)

    def test_exception_message(self):
        """Make sure the message from a non-HTTPException is elided."""
        msg = "Something went terribly wrong"
        resp = self.func(Request(_env()), ValueError(msg))
        self.assertNotEqual(json.loads(resp.body)['detail'], msg)


class DebugExceptionToResponseTest(ExceptionToResponseTest):

    def setUp(self):
        ExceptionToResponseTest.setUp(self)
        self.func = _debug_exception_to_reponse

    def test_httpexception_message(self):
        """Make sure the message from a HTTPException is preserved."""
        msg = "foo"
        resp = self.func(Request(_env()), exc.HTTPBadRequest(msg))
        body = json.loads(resp.body)
        self.assertTrue(msg in body['detail'])
        self.assertTrue('HTTPBadRequest' in body['detail'])

    def test_traceback_object(self):
        """Make sure tracebacks are included when they're objects."""
        try:
            raise Exception("foo")
        except Exception, ex:
            ex.__traceback__ = sys.exc_info()[-1]

        resp = self.func(Request(_env()), ex)
        body = json.loads(resp.body)
        self.assertTrue('traceback' in body)
        self.assertNotEqual(body['traceback'], "No traceback available.")

    def test_no_traceback(self):
        """Make sure lack of tracebacks doesn't break Dream."""
        resp = self.func(Request(_env()), Exception("foo"))
        body = json.loads(resp.body)
        self.assertTrue('traceback' in body)
        self.assertEqual(body['traceback'], ["No traceback available"])


class DebugTest(unittest.TestCase):

    """Make sure the debug option works."""

    def test_debug_value(self):
        self.assertTrue(App(debug=True).debug)
        self.assertFalse(App().debug)

    def test_debug_exceptions(self):
        """Make sure exceptions are handled properly based on debug."""
        app = App(debug=True)
        resp = app._mangle_response(
            Request(_env()), exc.HTTPInternalServerError("Whops"))
        self.assertTrue('traceback' in json.loads(resp.body))

    def test_nondebug_exceptions(self):
        """Make sure exceptions are handled properly based on debug."""
        app = App(debug=False)
        resp = app._mangle_response(
            Request(_env()), exc.HTTPInternalServerError("Whops"))
        self.assertFalse('traceback' in json.loads(resp.body))


class MangleResponseTest(unittest.TestCase):

    """Make sure _mangle_response works."""

    def setUp(self):
        self.app = App(debug=True)

    def test_exceptions(self):
        """Make sure exceptions are handled properly."""
        exc = ValueError("Expected some cheese.")
        resp = self.app._mangle_response(Request(_env()), exc)
        body = json.loads(resp.body)
        self.assertTrue(body['detail'].startswith('Caught exception ' +
                                                  str(type(exc))))

    def test_traceback_list(self):
        """Make sure tracebacks are included when they're lists."""
        ex = Exception("foo")
        ex.__traceback__ = traceback.extract_stack()

        resp = _debug_exception_to_reponse(Request(_env()), ex)
        body = json.loads(resp.body)
        self.assertTrue('traceback' in body)
        self.assertNotEqual(body['traceback'], ["No traceback available."])

    def test_nonerror_exceptions(self):
        """Non-error exceptions shouldn't get mangled a traceback."""
        ex = exc.HTTPMovedPermanently(headers={'Location': "/foo.json"})
        resp = self.app._mangle_response(Request(_env()), ex)
        self.assertTrue(resp is ex)

    def test_server_error_exceptions(self):
        """Non-error exceptions shouldn't get mangled a traceback."""
        ex = exc.HTTPInternalServerError()
        resp = self.app._mangle_response(Request(_env()), ex)
        self.assertTrue(resp is not ex)

    def test_client_error_exceptions(self):
        """Non-error exceptions shouldn't get mangled a traceback."""
        ex = exc.HTTPBadRequest()
        resp = self.app._mangle_response(Request(_env()), ex)
        self.assertTrue(resp is not ex)


class MultipleExposeTest(unittest.TestCase):

    """Test exposing the same function under multiple URLs."""

    def test_multi_expose(self):
        app = App()

        @app.expose("/foo")
        @app.expose("/bar")
        def endpoint(request):
            return Response(body="Hi.")

        (req, resp) = app.route({'REQUEST_METHOD': "GET",
                                 'PATH_INFO': "/foo"})
        self.assertTrue(isinstance(resp, Response))
        self.assertFalse(isinstance(resp, exc.HTTPError))
        self.assertTrue(resp.body == "Hi.")


class FormatTracebackTest(unittest.TestCase):

    """Test _format_traceback."""

    def test_no_traceback(self):
        tbk = _format_traceback(Exception())
        self.assertTrue(isinstance(tbk, (list, tuple)))
        self.assertTrue(len(tbk) == 1)
        self.assertTrue(tbk == ["No traceback available"])

    def test_traceback_object(self):
        try:
            raise Exception("Boo")
        except Exception, ex:
            ex.__traceback__ = sys.exc_info()[-1]

        tbk = _format_traceback(ex)
        self.assertTrue(isinstance(tbk, (list, tuple)))
        self.assertTrue(len(tbk) > 0)
        self.assertTrue('test_traceback_object' in tbk[-1])

    def test_traceback_list(self):
        ex = Exception("Boo")
        ex.__traceback__ = traceback.extract_stack()

        tbk = _format_traceback(ex)
        self.assertTrue(isinstance(tbk, (list, tuple)))
        self.assertTrue(len(tbk) > 0)
        self.assertTrue('test_traceback_list' in tbk[-1])


class TestHidden(unittest.TestCase):

    """Test the @hidden decorator."""

    def test_decorator(self):
        """Test the decorator itself."""

        func = lambda: None
        func_ = hidden(func)
        self.assertTrue(func is func_)
        self.assertTrue(hasattr(func_, '__hidden__'))
        self.assertTrue(func.__hidden__)

    def test_endpoints(self):
        """Make sure hidden functions don't show up in endpoints."""
        app = App()

        @app.expose('/endpoint')
        @hidden
        def endpoint(request):
            return Response()

        self.assertFalse(app.endpoints())


class RequestTest(unittest.TestCase):

    """Test Dream's request object."""

    def test_has_id(self):
        self.assertTrue(hasattr(Request(_env()), 'id'))

    def test_id_immutable(self):
        x = Request(_env())
        self.assertEqual(x.id, x.id)

    def test_id_unique(self):
        self.assertNotEqual(Request(_env()).id, Request(_env()).id)

    def test_provide_id(self):
        x = Request(_env(), id=123)
        self.assertEqual(x.id, 123)


if __name__ == '__main__':
    unittest.main()

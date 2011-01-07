# -*- coding: utf-8 -*-
#
# © 2010, 2011 SimpleGeo, Inc. All rights reserved.
# Author: Ian Eure <ian@simplegeo.com>
#

"""Tests for Dream."""

import unittest
import json

from webob.multidict import UnicodeMultiDict
from dream import (App, Request, Response, JSONResponse,
                   HumanReadableJSONResponse, exc,
                   endpoints, _wrap_endpoint, _exception_to_response,
                   _debug_exception_to_reponse)


class WrapEndpointTest(unittest.TestCase):

    """Tests for the _wrap_endpoint function."""

    def test_generates_request(self):
        """Make sure request objects are generated."""
        runs = []

        def test_f(request):
            runs.append(True)
            self.assert_(isinstance(request, Request))
            return Response()

        test_f_prime = _wrap_endpoint(test_f)
        output = test_f_prime({'HTTP_X_SIMPLEGEO_USER': 'jcleese'})
        self.assert_(len(runs) == 1)

    def test_http_exceptions_returned(self):
        """Make sure HTTPExceptions are returned."""
        ex = exc.HTTPException(000, "Test exception")

        def test_f(request):
            raise ex

        test_f_prime = _wrap_endpoint(test_f)
        output = test_f_prime({'HTTP_X_SIMPLEGEO_USER': 'jcleese'})
        self.assert_(output is ex)

    def test_exceptions_returned(self):
        """Make sure non-HTTPExceptions are returned."""
        ex = Exception("Test exception")

        def test_f(request):
            raise ex

        test_f_prime = _wrap_endpoint(test_f)
        resp = test_f_prime({'HTTP_X_SIMPLEGEO_USER': 'jcleese'})
        self.assert_(resp is ex)

    def test_preserves_docstring(self):
        """Make sure the docstring is preserved in the wrapper function."""
        def endpoint(request):
            """This a test endpoint with some documentation."""
            pass

        endpoint_prime = _wrap_endpoint(endpoint)
        self.assert_(endpoint_prime.__doc__ == endpoint.__doc__)

    def test_bad_request_missing_header(self):
        """Ensure BadRequest is returned when X-Simplegeo-User is missing"""
        endpoint_prime = _wrap_endpoint(lambda req: None)
        resp = endpoint_prime({'REQUEST_METHOD': 'POST'})
        self.assertTrue(isinstance(resp, exc.HTTPBadRequest))

    def test_bad_request_missing_header(self):
        """Ensure BadRequest is not returned when user is missing on GETs."""
        endpoint_prime = _wrap_endpoint(lambda req: "test")
        resp = endpoint_prime({'REQUEST_METHOD': 'GET'})
        self.assertEquals(resp, "test")

    def test_unicode_request(self):
        """Make sure the request uses Unicode."""
        env = {'QUERY_STRING': 'q=ü'}
        def __endpoint__(request):
            self.assertTrue(isinstance(request.GET, webob.UnicodeMultiDict))

        _wrap_endpoint(__endpoint__)(env)


class JSONResponseTest(unittest.TestCase):

    """Test the JSONResponse."""

    resp_class = JSONResponse

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


class HumanReadableJSONResponseTest(JSONResponseTest):
    resp_class = HumanReadableJSONResponse


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
        self.assert_(self.app.map[method]._patterns[url][1] is not f)

    def test_expose_method_decorates(self):
        """Make sure functions are decorated when added."""
        url, method = ('/shop', 'GET')
        old_len = len(self.app.map[method]._patterns)
        f = lambda request: None
        self.app.expose(url, method)(f)
        self.assert_(self.app.map[method]._patterns[url][1] is not f)


class RenderTest(unittest.TestCase):

    def setUp(self):
        self.app = App()

    def test_httpexception(self):
        ex = exc.HTTPNotFound(detail="test")
        out = self.app._render({}, ex)
        print out
        self.assertTrue(out[0].startswith('404'))

    def test_non_httpexception(self):
        ex = ValueError("WTF")
        out = self.app._render({}, ex)
        self.assertTrue(out[0].startswith("500"))

    def test_json_type(self):
        ex = ValueError("WTF")
        out = self.app._render({}, ex)
        headers = dict(out[1])
        self.assertTrue('Content-Type' in headers)
        self.assertEqual(headers['Content-Type'], 'application/json')

    def test_bad_response(self):
        resp = self.app._render({}, "foo")
        self.assertTrue(isinstance(resp, tuple))
        self.assertTrue(resp[0].startswith("500"))


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
        self.assertTrue(isinstance(
                self.app.route({'REQUEST_METHOD': 'GET',
                                'PATH_INFO': '/endpoints'}),
                HumanReadableJSONResponse))


class RouteTest(unittest.TestCase):

    """Test App.route()."""

    def test_prefix_404(self):
        app = App(prefix='/1.0')
        self.assertRaises(exc.HTTPNotFound, app.route,
                          {'REQUEST_METHOD': 'GET',
                           'PATH_INFO': '/foo'})

    def test_nonprefix_404(self):
        app = App()
        self.assertRaises(exc.HTTPNotFound, app.route,
                          {'REQUEST_METHOD': 'GET',
                           'PATH_INFO': '/foo'})

    def test_success(self):
        response = Response(body="Hi")
        app = App()
        app.expose('/')(lambda request: response)
        resp = app.route({'REQUEST_METHOD': 'GET',
                           'PATH_INFO': '/'})
        self.assertTrue(resp is response)


class ExceptionToResponseTest(unittest.TestCase):

    def test_types(self):
        resp = _exception_to_response(Exception("foo"))
        self.assertTrue(isinstance(resp, Response))

    def test_status(self):
        """Make sure webob exception statuses are preserved."""
        not_found = exc.HTTPNotFound("Sorry")
        resp = _exception_to_response(not_found)
        self.assertEqual(not_found.status, resp.status)

    def test_has_detail(self):
        """Make sure there's error detail."""
        resp = _exception_to_response(Exception("foo"), "cookie")
        body = json.loads(resp.body)
        self.assertTrue('detail' in body)

    def test_has_cookie(self):
        """Make sure the cookie is included."""
        resp = _exception_to_response(Exception("foo"), "cookie")
        body = json.loads(resp.body)
        self.assertTrue('cookie' in body)
        self.assertEqual(body['cookie'], 'cookie')

    def test_no_traceback(self):
        """Make sure there is no traceback."""
        resp = _exception_to_response(Exception("foo"), "cookie")
        self.assertFalse('traceback' in json.loads(resp.body))

    def test_httpexception_message(self):
        """Make sure the message from a HTTPException is preserved."""
        msg = "foo"
        resp = _exception_to_response(exc.HTTPBadRequest(msg), "cookie")
        self.assertEqual(json.loads(resp.body)['detail'], msg)

    def test_exception_message(self):
        """Make sure the message from a non-HTTPException is elided."""
        msg = "Something went terribly wrong"
        resp = _exception_to_response(ValueError(msg), "cookie")
        self.assertNotEqual(json.loads(resp.body)['detail'], msg)


class DebugExceptionToResponseTest(unittest.TestCase):

    def test_types(self):
        resp = _debug_exception_to_reponse(Exception("foo"))
        self.assertTrue(isinstance(resp, Response))

    def test_status(self):
        """Make sure webob exception statuses are preserved."""
        not_found = exc.HTTPNotFound("Sorry")
        resp = _debug_exception_to_reponse(not_found)
        self.assertEqual(not_found.status, resp.status)

    def test_has_detail(self):
        """Make sure there's error detail."""
        resp = _debug_exception_to_reponse(Exception("foo"), "cookie")
        body = json.loads(resp.body)
        self.assertTrue('detail' in body)

    def test_has_cookie(self):
        """Make sure the cookie is included."""
        resp = _debug_exception_to_reponse(Exception("foo"), "cookie")
        body = json.loads(resp.body)
        self.assertTrue('cookie' in body)
        self.assertEqual(body['cookie'], 'cookie')

    def test_has_traceback(self):
        """Make sure there is a traceback."""
        resp = _debug_exception_to_reponse(Exception("foo"), "cookie")
        self.assertTrue('traceback' in json.loads(resp.body))


class DebugTest(unittest.TestCase):

    """Make sure the debug option works."""

    def test_debug_value(self):
        self.assertTrue(App(debug=True).debug)
        self.assertFalse(App().debug)

    def test_debug_exceptions(self):
        """Make sure exceptions are handled properly based on debug."""
        app = App(debug=True)
        resp = app._mangle_response(exc.HTTPBadRequest("Whops"))
        self.assertTrue('traceback' in json.loads(resp.body))

    def test_nondebug_exceptions(self):
        """Make sure exceptions are handled properly based on debug."""
        app = App(debug=False)
        resp = app._mangle_response(exc.HTTPBadRequest("Whops"))
        self.assertFalse('traceback' in json.loads(resp.body))


if __name__ == '__main__':
    unittest.main()

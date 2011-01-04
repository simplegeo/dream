# -*- coding: utf-8 -*-
#
# © 2010, 2011 SimpleGeo, Inc. All rights reserved.
# Author: Ian Eure <ian@simplegeo.com>
#

"""Tests for Dream."""

import unittest
import json

from dream import (App, Request, Response, JSONResponse,
                   HumanReadableJSONResponse, exc,
                   endpoints, _wrap_endpoint)


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


class HTTPExceptionMixinTest(unittest.TestCase):

    def test_has_json_response(self):
        ex = exc.HTTPBadRequest(detail="test 123",
                                comment="Hiii")
        self.assertTrue(hasattr(ex, 'json_response'))
        resp = ex.json_response()
        self.assertTrue(isinstance(resp, Response))
        self.assertEqual(resp.status, ex.status)
        body = json.loads(resp.body)
        self.assertTrue('detail' in body)
        self.assertTrue(body['detail'] == ex.detail)
        self.assertTrue('comment' in body)
        self.assertTrue(body['comment'] == ex.comment)


class RenderTest(unittest.TestCase):

    def setUp(self):
        self.app = App()

    def test_httpexception(self):
        ex = exc.HTTPNotFound(detail="test")
        out = self.app._render({}, ex)
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


if __name__ == '__main__':
    unittest.main()

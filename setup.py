# -*- coding: utf-8 -*-
#
# © 2010, 2011 SimpleGeo, Inc. All rights reserved.
# Author: Ian Eure <ian@simplegeo.com>
#

from setuptools import setup, find_packages


setup(name="dream",
      version=0,
      install_requires=['webob',
                        'decoroute'],
      tests_require=['nose',
                     'mock'],
      test_suite="nose.collector",)

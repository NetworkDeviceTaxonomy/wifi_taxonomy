#!/usr/bin/python
# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for taxonomy/ssdp.py."""

__author__ = 'dgentry@google.com (Denton Gentry)'


import unittest
import ssdp


class SsdpTaxonomyTest(unittest.TestCase):
  """Unit tests for ssdp.py."""

  def testDescribe(self):
    self.assertEqual(ssdp.describe_ssdp_device(''), '')
    self.assertEqual(
        ssdp.describe_ssdp_device('OpenRG/6.0.7.1.4 UPnP/1.0'),
        'Google Fiber GFRG1x0')
    self.assertEqual(
        ssdp.describe_ssdp_device('not_a_real_server'),
        'SHA:fc115a1c81d6de5c1ad9b433f35de1254d40b6879a5322a865e95c1d7db22850')


if __name__ == '__main__':
  unittest.main()

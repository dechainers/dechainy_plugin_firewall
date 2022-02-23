# Copyright 2022 DeChainers
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import unittest
import os

from dechainy.controller import Controller

controller = Controller()


@unittest.skipIf(os.getuid(), reason='Root for BCC')
class TestFirewall(unittest.TestCase):

    @classmethod
    def tearDownClass(cls) -> None:
        controller.delete_probe(plugin_name='firewall')
        controller.delete_plugin('firewall')

    def test1_add_plugin(self):
        controller.create_plugin(os.path.join(os.path.dirname(
            __file__), os.pardir, "firewall"), update=True)

    def test2_create_probe(self):
        controller.create_probe('firewall', "attempt", interface="lo")

    def test3_insert_rule(self):
        rule = controller.get_plugin('firewall').FirewallRule(src='8.8.8.8')
        p = controller.get_probe('firewall', 'attempt')
        p.insert('ingress', rule)
        assert len(p.get('ingress')) == 1

    def test4_insert_error(self):
        rule = controller.get_plugin('firewall').FirewallRule(src='8.8.8.8')
        p = controller.get_probe('firewall', 'attempt')
        with self.assertRaises(LookupError):
            p.insert('ingress', rule)

    def test5_delete_rule(self):
        rule = controller.get_plugin('firewall').FirewallRule(src='8.8.8.8')
        p = controller.get_probe('firewall', 'attempt')
        p.delete('ingress', rule)
        assert len(p.get('ingress')) == 0

    def test6_insert_at_error(self):
        rule = controller.get_plugin('firewall').FirewallRule(src='8.8.8.8')
        p = controller.get_probe('firewall', 'attempt')
        with self.assertRaises(IndexError):
            p.insert_at('ingress', 10, rule)


if __name__ == '__main__':
    unittest.main()

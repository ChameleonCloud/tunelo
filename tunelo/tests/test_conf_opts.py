from oslotest import base

from tunelo.conf import opts


class ListOptsTest(base.BaseTestCase):
    def test_sample_config_includes_tunelo_sections(self):
        """The sample config is generated from list_opts()."""
        sections = {
            group: [opt.dest for opt in options]
            for group, options in opts.list_opts()
        }

        self.assertIn("default_subnet", sections["DEFAULT"])
        self.assertIn("valid_interfaces", sections["neutron"])

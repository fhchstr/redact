import unittest
import os
import sys

# https://docs.python-guide.org/writing/structure/
project_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_directory)

from redact import Redacter

class TestRedacter(unittest.TestCase):

    def test_init_invalid(self):
        with self.assertRaises(AttributeError):
            self.assertraisesRedacter('test')

    def test_init_substitutions(self):
        s = {'secret': 'substitution'}
        r = Redacter('redact', substitutions=s)
        self.assertEqual(r.substitutions, s)

    def test_init_patterns(self):
        p = [r'test']
        r = Redacter('redact', patterns=p)
        self.assertEqual(len(r.patterns[0].search('This is a test').groups()), 1)

    def test_redact_with_substitutions(self):
        s = {'secretA': 'x', 'secretB': 'y'}
        r = Redacter('redact', substitutions=s)
        self.assertEqual(r.redact('secretA'), 'x')
        self.assertEqual(r.redact(' secretA'), ' x')
        self.assertEqual(r.redact('secretA '), 'x ')
        self.assertEqual(r.redact('secretAsecretA'), 'xx')
        self.assertEqual(r.redact('secretA secretA'), 'x x')
        self.assertEqual(r.redact('secretAsecretB'), 'xy')

    def test_redact_with_patterns(self):
        p = [r'secretA', 'secret: (\S+)']
        r1 = Redacter('redact', patterns=p)
        r2 = Redacter('redact', patterns=p)
        self.assertEqual(r1.redact('secretA'), 'redact0')
        self.assertEqual(r2.redact('secret: x'), 'secret: redact0')
        self.assertEqual(r1.redact('secret: x'), 'secret: redact1')
        self.assertEqual(r1.redact('x'), 'redact1')

    def test_redact_with_patterns_substring(self):
        p = [r'A\S*']
        r = Redacter('redact', patterns=p)
        self.assertEqual(r.redact('A'), 'redact0')
        self.assertEqual(r.redact('AA'), 'redact1')
        self.assertEqual(r.redact('AB'), 'redact2')
        self.assertEqual(r.redact('XAB'), 'Xredact2')

    def test_redact_with_patterns_and_substitutions(self):
        p = [r'secret: (\S+)']
        s = {'test': 'x'}
        r = Redacter('redact', patterns=p, substitutions=s)
        self.assertEqual(r.redact('secret: test'), 'secret: x')
        self.assertEqual(r.redact('secret: te'), 'secret: redact0')
        self.assertEqual(r.redact('secret: tes'), 'secret: redact1')
        self.assertEqual(r.redact('test'), 'x')
        self.assertEqual(r.redact('te'), 'redact0')
        self.assertEqual(r.redact('tes'), 'redact1')

    def test_redact_with_pattens_secret_in_text(self):
        # Using the example from the README (chapter "Caveats")
        p = [r'using password "(.+)"$']
        r = Redacter('secret', patterns=p)
        self.assertEqual(
            r.redact('authentication successful using password "password"'),
            'authentication successful using secret0 "secret0"',
        )

    def test_redact_with_validator(self):
        p = [r'\d+\.\d+\.\d+\.\d+']
        v = os.path.join(
            project_directory,
            'tests', 'config', 'etc', 'redact', 'validators', 'ipv4_address'
        )
        r = Redacter('redact', patterns=p, validator=v)
        self.assertEqual(r.redact('10.10.255.1'), 'redact0')
        self.assertEqual(r.redact('10.10.299.1'), '10.10.299.1')

#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# Author:  Fabien Hochstrasser
# Date:    2019-02-05
# Purpose: Redact a file by replacing secret values by placeholders.
#
import argparse
import os
import re
import subprocess
import sys

from collections import defaultdict


CONFIG_DIRS = [
    os.path.join(os.path.expanduser('~'), '.redact'),
    os.path.join(os.path.abspath(os.sep), 'etc', 'redact'),
]
PATTERNS = 'patterns'
SUBSTITUTIONS = 'substitutions'
VALIDATORS = 'validators'


def main(args):
    """Redact the files one-by-one, in the order they are given.

    There is a 1-to-1 mapping between the secrets and their substitutions across
    all the files redacted during the same run.
    """
    config_dirs = args.conf if args.no_default else args.conf + CONFIG_DIRS
    config = get_config(config_dirs)

    # Redact all the secrets found in the config if --secrets isn't specified
    secrets = args.secrets if args.secrets else config.keys()
    redacters = [
        Redacter.create(
            substitution_string=secret,
            regex_file=config[secret][PATTERNS],
            substitutions_file=config[secret][SUBSTITUTIONS],
            validator_file=config[secret][VALIDATORS],
        )
        for secret in config if secret in secrets
    ]
    # Redacter.create() returns None When no useful configuration was found
    redacters = filter(lambda x: x is not None, redacters)

    if not redacters:
        print('Couldn\'t parse any configuration file')
        sys.exit(1)

    with open(args.file, 'r') as f:
        for line in f:
            for redacter in redacters:
                line = redacter.redact(line)
            sys.stdout.write(line)

    # Write the substitutions to the disk
    if not args.write_substitutions:
        return
    for redacter in redacters:
         with open(os.path.join(args.write_substitutions, redacter.substitution_string), 'w') as f:
             for secret in redacter.substitutions:
                 f.write('{} = {}\n'.format(secret, redacter.substitutions[secret]))


def get_config(config_dirs):
    """Return the secrets and their configuration files.

    For each `config_type` (patterns, substitutions, validators), the first
    configuration file found is returned.

    Args:
        config_dirs: The configuration directories to traverse (in that order),
                     as a list of paths (string).

    Returns: A dict (key=secret name) of dicts (key=config_type) of file paths.
    """
    secrets = defaultdict(lambda: defaultdict(lambda: None))

    for d in config_dirs:
        for config_type in [PATTERNS, SUBSTITUTIONS, VALIDATORS]:
            try:
                files = os.listdir(os.path.join(d, config_type))
            except OSError:
                # Don't crash for non-existing directories
                continue

            for name in files:
                # Don't overwrite existing values, the first one found is kept
                if config_type not in secrets[name]:
                    secrets[name][config_type] = os.path.join(d, config_type, name)
            
    return secrets


def read_uncommented_lines(filename):
    """Yields the uncommented lines read from filename."""
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                yield line
    except:
        # Stop if the file cannot be read
        return


class Redacter(object):
    """A Redacter instance keeps track of the required information to redact a string.

    To identify a secret string, a Redacter uses regular expressions which must
    have EXACTLY one matching group. The string captured by this group can be
    validatated by the `validator` script.
    The information used by a Redacter instance is the following:
      - cleartext-to-secret "translations"

    Attributes:
        patterns: A list of compiled regex used to identify potential secrets (identified by patterns)
        substitution: The "redacted" string used to replace a secret string
        substitutions: A (pre-filled) dict which keeps track of the cleartext/redacted relationships
        validator: Path to the validator script
    """
    def __init__(self, substitution_string, patterns=None, substitutions=None, validator=None):
        """Initialize a Redacter instance.

        Args:
            substitution_string: A string used to replace the secrets found. Each secret is replaced
                                 by a unique string. In the redacted output, a suffix is added to
                                 the substitution_string, to ensure its uniqueness. The keys are the
                                 secrets and their value the anonymized string replacing it.
            patterns: A list of regular expressions used to identify potential (see
                      `validator` arg) secrets to be redacted. Each regex must have at
                      most one capturing group identifying the secret string.  If it
                      doesn't have any, the whole regex is the secret.
            substitutions: A dict of pre-defined substitutions. It is the responsibility of the user
                           to ensure their uniqueness. The Reacter doesn't add a suffix to those. 
            validator: Path to a script taking a potential secret string as argument. It's called
                       for each new secret identified. A return code of zero means the secret is
                       validated.
        """
        if not patterns and not substitutions:
            raise AttributeError('At least patterns or substitutions must be defined')

        self.substitution_string = substitution_string
        self.patterns = (
            [Redacter.compile_regex(r) for r in patterns]
            if patterns else []
        )
        self.substitutions = substitutions if substitutions else {}

        # To ensure the uniqueness of the secret strings used to anonymize their
        # cleartext counterpart, a number (incremented for each new secret) is
        # appended at the end of the secret string
        self._counter = 0

        self.validator = validator

    @staticmethod
    def create(substitution_string, regex_file, substitutions_file, validator_file):
        """
        Return a Redacter instance initialized with the content of the configuration
        files passed as argument.

        Args:
            substitution_string: The name of the secret to redact, as a string.
            regex_file: The path of the file containing the regular expressions used to identify
                        potential secrets, as a string.
            substitutions_file: The path of the file containing the pre-defined substitutions for
                                this redacter (format <secret>=<anonymized string>), as a string
            validator_file: The path of the script used to validate potential secrets identifed by
                            the regular expression(s), as a string

        Returns: A Redacter instance or None if the the creation failed.
        """
        patterns = [line for line in read_uncommented_lines(regex_file)]

        substitutions = {
            '='.join(parts[:-1]).strip(): parts[-1].strip()
            for parts in [
                line.split('=')
                for line in read_uncommented_lines(substitutions_file)
            ]
        }

        try:
            return Redacter(
                substitution_string=substitution_string,
                patterns=patterns,
                substitutions=substitutions,
                validator=validator_file,
            )
        except AttributeError as e:
            return None

    @staticmethod
    def compile_regex(regex):
        """Validate and return the compiled regular expression.

        If the regular expressions doesn't have any capturing group, the whole
        regex is considered as a capturing group. If the regex has more than 1
        capturing group, it's invalid.
        """
        compiled = re.compile(regex)

        if compiled.groups > 1:
            raise AttributeError((
                'regular_expression "{0}" is invalid. It should have at '
                'most 1 capturing group'
            ).format(regex))

        if compiled.groups == 0:
            compiled = re.compile('({0})'.format(regex))

        return compiled

    def redact(self, string):
        """Return the redacted version of the given string.

        Args:
            string: The string to redact.

        Returns: The redacted version of the string.
        """
        # Make sure each secret found has a substitution string defined
        for pattern in self.patterns:
            for secret in pattern.findall(string):
                # Skip the secret if it already has a substitution string
                if secret in self.substitutions:
                    continue
                if self.validate(secret):
                    substitution = '{0}{1}'.format(self.substitution_string, self._counter)
                    self._counter += 1
                    self.substitutions[secret] = substitution

        # Redact the string replacing each secret with its substitution string.
        # The longest secrets are readacted first because some secrets might be
        # substrings of other secrets (e.g. IP addresses)
        for secret, substitution in sorted(
            self.substitutions.iteritems(),
            key=lambda i: len(i[0]),
            reverse=True
        ):
            string = string.replace(secret, self.substitutions[secret])

        return string

    def validate(self, secret):
        """Return True if the secret is really a secret.

        The validator script is used to decide.

        Args:
            secret: A string which is potentially a secret

        Returns: True if the string is a secret, false otherwise.
        """
        if not self.validator:
            return True

        with open(os.devnull, 'w') as devnull:
            return subprocess.call([self.validator, secret], stdout=devnull) == 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Redact a file by replacing secret values by placeholders.',
    )
    parser.add_argument(
        '--conf', '-c',
        nargs='+',
        default=[],
        help='path to additional configuration directory',
    )
    parser.add_argument(
        '--no-default', '-n',
        action='store_true',
        help='don\'t use the default configuration directories',
    )
    parser.add_argument(
        '--secrets', '-s',
        nargs='+',
        help='only redact those secrets',
    )
    parser.add_argument(
        '--write-substitutions', '-w',
        help='write the substitution to that directory',
    )
    parser.add_argument(
        'file',
        metavar='file',
        help='file to be anonymized',
    )

    args = parser.parse_args()

    if args.no_default and not args.conf:
        print('Cannot use --no-default without --conf')
        sys.exit(1)

    main(args)

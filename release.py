#!/usr/bin/env python3

import subprocess


def get_version():
    """
    print current version
    """
    try:
        check = "git describe --tags"
        out = subprocess.check_output(
            ["/bin/sh", "-c", check], stderr=subprocess.STDOUT, timeout=3
        )
    except KeyboardInterrupt:
        return "Unknown"
    except BaseException:
        check = "git describe --always"
        try:
            out = subprocess.check_output(
                ["/bin/sh", "-c", check], stderr=subprocess.STDOUT, timeout=3
            )
        except BaseException:
            return "Unknown"

    return out.decode("utf-8").strip()


with open("./core/.version", "w+", encoding='utf-8') as f:
    f.write(get_version())

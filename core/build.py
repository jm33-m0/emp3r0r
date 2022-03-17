#!/usr/bin/env python3

# pylint: disable=invalid-name, too-many-branches, too-many-statements, broad-except, too-many-arguments, too-many-instance-attributes, line-too-long

"""
this script replaces build.sh, coz bash/sed/awk is driving me insane
"""

import argparse
import atexit
import glob
import json
import os
import random
import readline
import shutil
import sys
import traceback
import uuid


class GoBuild:
    """
    all-in-one builder
    """

    def __init__(
        self,
        target="cc",
        cc_indicator="",
        cc_host="",
        cc_other_names="",
    ):
        self.target = target
        self.GOOS = os.getenv("GOOS")
        self.GOARCH = os.getenv("GOARCH")

        if self.GOOS is None:
            self.GOOS = "linux"

        if self.GOARCH is None:
            self.GOARCH = "amd64"

        # CA
        self.CA = ""

        # tags
        self.CCHost = cc_host
        self.CC_OTHER_NAMES = cc_other_names
        self.INDICATOR = cc_indicator
        self.UUID = str(uuid.uuid1())

        # webroot

        if "webroot" in CACHED_CONF:
            self.WebRoot = CACHED_CONF["webroot"]
        else:
            self.WebRoot = str(uuid.uuid1())
            CACHED_CONF["webroot"] = self.WebRoot

        # OpSep

        if "opsep" in CACHED_CONF:
            self.OpSep = CACHED_CONF["opsep"]
        else:
            self.OpSep = str(uuid.uuid1())
            CACHED_CONF["opsep"] = self.OpSep

        # pid file name

        if "pid_file" in CACHED_CONF:
            self.PIDFile = CACHED_CONF["pid_file"]
        else:
            self.PIDFile = rand_str(random.randint(3, 10))
            CACHED_CONF["pid_file"] = self.PIDFile

        # indicator text

        if "indicator_text" in CACHED_CONF:
            self.INDICATOR_TEXT = CACHED_CONF["indicator_text"]
        else:
            self.INDICATOR_TEXT = "emp3r0r"
            CACHED_CONF["indicator_text"] = self.INDICATOR_TEXT

        # agent root directory

        if "agent_root" in CACHED_CONF:
            self.AgentRoot = CACHED_CONF["agent_root"]
        else:
            # by default mkdir in current directory
            self.AgentRoot = f"{rand_str(random.randint(5, 10))}"

            if self.GOOS == "linux":
                self.AgentRoot = "/tmp/" + self.AgentRoot

            CACHED_CONF["agent_root"] = self.AgentRoot

        # util path name

        if "utils_path" in CACHED_CONF:
            self.UtilsPath = CACHED_CONF["utils_path"]
        else:
            self.UtilsPath = f"{self.AgentRoot}/{rand_str(random.randint(3, 10))}"
            CACHED_CONF["utils_path"] = self.UtilsPath

        # socket name

        if "socket" in CACHED_CONF:
            self.Socket = CACHED_CONF["socket"]
        else:
            self.Socket = f"{self.AgentRoot}/{rand_str(random.randint(3, 10))}"
            CACHED_CONF["socket"] = self.Socket

        # DoH

        if "doh_server" not in CACHED_CONF:
            CACHED_CONF["doh_server"] = ""

        # agent proxy

        if "agent_proxy" not in CACHED_CONF:
            CACHED_CONF["agent_proxy"] = ""

        # cdn proxy

        if "cdn_proxy" not in CACHED_CONF:
            CACHED_CONF["cdn_proxy"] = ""

    def build(self):
        """
        cd to cmd and run go build
        """
        self.gen_certs()
        # CA

        if "ca" in CACHED_CONF:
            log_warn(
                f"Using cached CA cert ({CACHED_CONF['ca']}),\nmake sure you have the coresponding keypair signed by it"
            )
            self.CA = CACHED_CONF["ca"]
        else:
            with open(f"{PWD}/tls/rootCA.crt", encoding="utf-8") as f:
                self.CA = f.read()

            # cache CA, too
            CACHED_CONF["ca"] = self.CA

        # write cached configs
        with open(BUILD_JSON, "w+", encoding="utf-8") as json_file:
            json.dump(CACHED_CONF, json_file, indent=4)

        try:
            # copy the server/cc keypair to ./ for later use

            if os.path.isdir(f"{PWD}/tls"):
                log_warn("[*] Copying CC keypair to ./")

                for f in glob.glob(f"{PWD}/tls/emp3r0r-*pem"):
                    print(f" Copy {f} to ./")
                    shutil.copy(f, f"{PWD}")

            try:
                os.chdir(f"{PWD}/cmd/{self.target}")
            except BaseException:
                log_error(f"Cannot cd to cmd/{self.target}")

                return

            log_warn("GO BUILD starts...")
            log_warn("------------------")
            build_target = f"{PWD}/{self.target}.exe"

            if self.target == "agent":
                build_target = f"{PWD}/stub.exe"

            # go mod

            if os.system("go mod tidy") != 0:
                if yes_no("go mod tidy failed, goodbye?"):
                    sys.exit(1)

            cmd = (
                f"""GOOS={self.GOOS} GOARCH={self.GOARCH} CGO_ENABLED=0"""
                + f""" go build -o {build_target} -ldflags='-s -w -v' -trimpath"""
            )

            # garble

            if shutil.which("garble") and self.target.startswith("agent"):
                if yes_no("Use garble to obfuscate agent binary?"):
                    cmd = (
                        f"""GOOS={self.GOOS} GOARCH={self.GOARCH} CGO_ENABLED=0 GOPRIVATE="""
                        + f""" garble -literals -tiny build -o {build_target} -ldflags="-v" -trimpath ."""
                    )
                    log_warn("Using garble to build agent binary")

            if os.system(cmd) != 0:
                log_error(f"failed to build {self.target}")

                if yes_no("Goodbye?"):
                    sys.exit(1)

            os.chdir(PWD)
        except (KeyboardInterrupt, EOFError, SystemError, SystemExit):
            log_error("Aborted")
        finally:
            # self.unset_tags()
            log_warn("GO BUILD ends...")
            log_warn("----------------")

        targetFile = f"{PWD}/{build_target.split('/')[-1]}"

        if os.path.exists(targetFile):
            log_success(f"{targetFile} generated")
        else:
            log_error("go build failed")
            sys.exit(1)

    def gen_certs(self):
        """
        generate server cert/key, and CA if necessary
        """

        if "cc_host" in CACHED_CONF:
            if self.CCHost == CACHED_CONF["cc_host"] and os.path.exists(
                f"{PWD}/emp3r0r-key.pem"
            ):
                return

        log_warn("[!] Generating new certs...")
        try:
            os.chdir(f"{PWD}/tls")
            os.system(
                f"bash ./genkey-with-ip-san.sh {self.UUID} {self.UUID}.com {self.CCHost} {self.CC_OTHER_NAMES}"
            )
            os.rename(f"./{self.UUID}-cert.pem", "./emp3r0r-cert.pem")
            os.rename(f"./{self.UUID}-key.pem", "./emp3r0r-key.pem")
            os.chdir(PWD)
        except BaseException as exc:
            log_error(
                f"[-] Something went wrong, see above for details: {exc}")
            sys.exit(1)


def clean():
    """
    clean build output
    """
    to_rm = (
        glob.glob("./tls/emp3r0r*")
        + glob.glob("./tls/openssl-*")
        + glob.glob(".//*")
        + glob.glob("./tls/*.csr")
    )

    for f in to_rm:
        try:
            # remove directories too

            if os.path.isdir(f):
                os.system(f"rm -rf {f}")
            else:
                # we don't need to delete the config file

                if f.endswith("emp3r0r.json"):
                    continue
                os.remove(f)
            log_success(" Deleted " + f)
        except BaseException:
            log_error(traceback.format_exc)


def sed(path, old, new):
    """
    works like `sed -i s/old/new/g file`
    """
    log_warn(f"{path}: {old}  ->  {new}")
    with open(path, encoding="utf-8") as rf:
        text = rf.read()
        to_write = text.replace(old, new)

    with open(path, "w", encoding="utf-8") as f:
        f.write(to_write)


def yes_no(prompt):
    """
    y/n?
    """

    if yes_to_all:
        log_warn(f"Choosing 'yes' for '{prompt}'")

        return True

    answ = input(prompt + " [Y/n] ").lower().strip()

    if answ in ["n", "no", "nah", "nay"]:
        return False

    return True


def rand_str(length):
    """
    random string
    """
    uuidstr = str(uuid.uuid4()).replace("-", "")

    # we don't want the string to be long

    if length >= len(uuidstr):
        return uuidstr

    return uuidstr[:length]


def main(target):
    """
    main main main
    """
    cc_host = ""
    indicator = ""
    use_cached = False

    if target == "clean":
        clean()

        return

    # cc IP

    if "cc_host" in CACHED_CONF:
        cc_host = CACHED_CONF["cc_host"]
        use_cached = yes_no(f"Use cached CC address ({cc_host})?")

    if not use_cached:
        if yes_no("Clean everything and start over?"):
            clean()
        cc_host = input(
            "CC server address (domain name or ip address, can be more than one, separate with space):\n> "
        ).strip()
        CACHED_CONF["cc_host"] = cc_host

        if len(cc_host.split()) > 1:
            CACHED_CONF["cc_host"] = cc_host.split()[0]

    if target == "cc":
        cc_other = ""

        if len(cc_host.split()) > 1:
            cc_other = " ".join(cc_host[1:])

        gobuild = GoBuild(target="cc", cc_host=cc_host,
                          cc_other_names=cc_other)
        gobuild.build()

        log_warn("\n\nBuilding cat...")
        cat_build = GoBuild(target="cat", cc_host=cc_host,
                            cc_other_names=cc_other)
        cat_build.build()

        return

    # indicator

    use_cached = False

    if "cc_indicator" in CACHED_CONF:
        indicator = CACHED_CONF["cc_indicator"]
        use_cached = yes_no(f"Use cached CC indicator ({indicator})?")

    if not use_cached:
        indicator = input(
            "CC status indicator URL (leave empty to disable): ").strip()
        CACHED_CONF["cc_indicator"] = indicator

    if CACHED_CONF["cc_indicator"] != "":
        # indicator text
        use_cached = False

        if "indicator_text" in CACHED_CONF:
            use_cached = yes_no(
                f"Use cached CC indicator text ({CACHED_CONF['indicator_text']})?"
            )

        if not use_cached:
            indicator_text = input(
                "CC status indicator text (leave empty to disable): "
            ).strip()
            CACHED_CONF["indicator_text"] = indicator_text

    # Agent proxy
    use_cached = False

    if "agent_proxy" in CACHED_CONF:
        use_cached = yes_no(
            f"Use cached agent proxy ({CACHED_CONF['agent_proxy']})?")

    if not use_cached:
        agentproxy = input(
            "Proxy server for agent (leave empty to disable): ").strip()
        CACHED_CONF["agent_proxy"] = agentproxy

    # CDN
    use_cached = False

    if "cdn_proxy" in CACHED_CONF:
        use_cached = yes_no(
            f"Use cached CDN server ({CACHED_CONF['cdn_proxy']})?")

    if not use_cached:
        cdn = input("CDN websocket server (leave empty to disable): ").strip()
        CACHED_CONF["cdn_proxy"] = cdn

    # DoH
    use_cached = False

    if "doh_server" in CACHED_CONF:
        use_cached = yes_no(
            f"Use cached DoH server ({CACHED_CONF['doh_server']})?")

    if not use_cached:
        doh = input("DNS over HTTP server (leave empty to disable): ").strip()
        CACHED_CONF["doh_server"] = doh

    # option to disable autoproxy and broadcasting

    if not yes_no("Use autoproxy (will enable UDP broadcasting)"):
        CACHED_CONF["broadcast_interval_max"] = 0

    gobuild = GoBuild(target=target, cc_indicator=indicator, cc_host=cc_host)
    gobuild.build()


def log_error(msg):
    """
    print in red
    """
    print("\u001b[31m" + msg + "\u001b[0m")


def log_warn(msg):
    """
    print in yellow
    """
    print("\u001b[33m" + msg + "\u001b[0m")


def log_success(msg):
    """
    print in green
    """
    print("\u001b[32m" + msg + "\u001b[0m")


def save(prev_h_len, hfile):
    """
    append to histfile
    """
    new_h_len = readline.get_current_history_length()
    readline.set_history_length(1000)
    readline.append_history_file(new_h_len - prev_h_len, hfile)


# remember working directory
PWD = os.getcwd()

# JSON config file, cache some user data
BUILD_JSON = f"{PWD}/emp3r0r.json"
CACHED_CONF = {}

if os.path.exists(BUILD_JSON):
    try:
        jsonf = open(BUILD_JSON)
        CACHED_CONF = json.load(jsonf)
        jsonf.close()
    except BaseException:
        log_warn(traceback.format_exc())


def rand_port():
    """
    returns a random int between 1024 and 65535
    """

    return str(random.randint(1025, 65534))


def randomize_ports():
    """
    randomize every port used by emp3r0r agent,
    cache them in emp3r0r.json
    """

    if "cc_port" not in CACHED_CONF:
        CACHED_CONF["cc_port"] = rand_port()

    if "sshd_port" not in CACHED_CONF:
        CACHED_CONF["sshd_port"] = rand_port()

    if "proxy_port" not in CACHED_CONF:
        CACHED_CONF["proxy_port"] = rand_port()

    if "broadcast_port" not in CACHED_CONF:
        CACHED_CONF["broadcast_port"] = rand_port()


# command line args
yes_to_all = False

parser = argparse.ArgumentParser(
    description="Build emp3r0r CC/Agent bianaries")
parser.add_argument(
    "--target", type=str, required=True, help="Build target, can be cc/agent"
)
parser.add_argument(
    "--garble",
    action="store_true",
    required=False,
    help="Obfuscate agent binary with garble",
)
parser.add_argument(
    "--yes",
    action="store_true",
    required=False,
    help="Do not ask questions, take default answers",
)
args = parser.parse_args()

if args.yes:
    yes_to_all = True

try:
    randomize_ports()

    # support GNU readline interface, command history
    histfile = f"{PWD}/.build_py_history"
    try:
        readline.read_history_file(histfile)
        h_len = readline.get_current_history_length()
    except FileNotFoundError:
        open(histfile, "wb").close()
        h_len = 0
    atexit.register(save, h_len, histfile)

    main(args.target)
    yes_no(f"{args.target} successfully built, goodbye?")

except (KeyboardInterrupt, EOFError, SystemExit):
    sys.exit(0)
except BaseException:
    log_error(f"[!] Exception:\n{traceback.format_exc()}")

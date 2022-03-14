import re
import string

from collections import defaultdict

from .model import DockerImageInfo

PASSWORD_KEYWORDS = (
    "pwd",
    "passwd"
    "password"
    "cred",
    "credential"
    "auth"
)

REGEX_URN = re.compile('[a-z\-]{0,6}://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
REGEX_IPV6 = re.compile(r'''(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,6}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}\Z)|(\A([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}\Z)|(\A([0-9a-f]{1,4}:){1,6}(:[0-9a-f]{1,4}){1,1}\Z)|(\A(([0-9a-f]{1,4}:){1,7}|:):\Z)|(\A:(:[0-9a-f]{1,4}){1,7}\Z)|(\A((([0-9a-f]{1,4}:){6})(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|(\A(([0-9a-f]{1,4}:){5}[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3})\Z)|(\A([0-9a-f]{1,4}:){5}:[0-9a-f]{1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,1}(:[0-9a-f]{1,4}){1,4}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,3}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,2}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,1}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A(([0-9a-f]{1,4}:){1,5}|:):(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)|(\A:(:[0-9a-f]{1,4}){1,5}:(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\Z)''')
REGEX_IPV4 = re.compile(r'''((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([
0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])) ''')
REGEX_EXTRACT_ENV_VAR = re.compile(r'''(\$[{]*[\w]+[}]*)''')
REGEX_EXTRACT_ENV_VAR_NAME = re.compile(r'''(\$[{]*)([\w]+)([}]*)''')


class DockerImageAnalysisResults:
    PASSWORD = "password"
    URN = "URL-IP"

    def __init__(self):
        self.running_user = ""
        self.sensitive_data = defaultdict(dict)
        self.warnings = defaultdict(set)

    def add_user(self, user_name):
        # if image_info.user == "" or image_info.working_dir == "/root":
        #     results.add_user("root")
        if not self.running_user:
            self.running_user = user_name
        elif self.running_user != "root" and user_name != "root":
            self.running_user = user_name

    def add_sensitive(self, sensitive_data_type, location, data):
        assert sensitive_data_type in (self.PASSWORD, self.URN)

        try:
            d = self.sensitive_data[sensitive_data_type][location]
            d.add(data)
        except KeyError:
            self.sensitive_data[sensitive_data_type][location] = set()
            self.sensitive_data[sensitive_data_type][location].add(data)

    def add_warning(self, location, message):
        self.warnings[location].add(message)


def _replace_bash_vars_in_string(text: str, image_metadata: list) -> str:
    # Extract var name
    var_name_mark = REGEX_EXTRACT_ENV_VAR.search(text).group(1)
    var_name = REGEX_EXTRACT_ENV_VAR_NAME.search(var_name_mark).group(2)

    # Search in environment vars
    for env in image_metadata:
        env_name, env_value = env.split("=", maxsplit=1)

        if var_name in env_name:
            text = text.replace(var_name_mark,
                                env_value)
            break
    return text


# --------------------------------------------------------------------------
# Content helpers function
# --------------------------------------------------------------------------
def _build_start_point(image_metadata) -> str:
    # Build the launching command
    entrypoint = image_metadata.entry_point

    if type(entrypoint) is list:
        entrypoint = " ".join(entrypoint)

    # Locate the entry-point
    cmd = image_metadata.cmd
    if image_metadata.cmd:
        if type(image_metadata.cmd) is list:
            cmd = " ".join(image_metadata.cmd)

    if entrypoint and cmd:
        start_point = "{} {}".format(entrypoint, cmd)
    elif entrypoint and not cmd:
        start_point = entrypoint
    elif not entrypoint and cmd:
        start_point = cmd
    else:
        start_point = ""

    return start_point.strip()


def _find_user_in_start_point(image_location: str,
                              start_point: str,
                              image_metadata: DockerImageInfo) -> str:
    launch_command = start_point

    is_binary = False
    # If start point is a shell script, then open it
    if launch_command.endswith("sh"):
        _shell_path = start_point[start_point.rfind(" ") + 1:]
        _shell_location = "{}/{}".format(image_location,
                                         _shell_path)

        # Clean
        _shell_location = _shell_location.replace("//", "/")

        # If command has any environment var -> replace it
        if "$" in _shell_location:
            _shell_location = _replace_bash_vars_in_string(
                _shell_location,
                image_metadata.environment)

        # Clean
        _shell_location = _shell_location.replace("//", "/")

        # Check if _shell is a binary file
        is_binary = open(_shell_location,
                         "r",
                         errors="ignore").read(1) in string.printable
        if not is_binary:
            launch_command = open(_shell_location, "r", errors="ignore").read()

    #
    # Try to find "sudo" or "gosu" or "su -c '...'"
    #
    SUDO_PATTERNS = ("sudo", "gosu", "su -c")
    if not is_binary:
        for pattern in SUDO_PATTERNS:
            if pattern in launch_command:
                return "non-root"
        else:
            return "root"
    else:
        return "root"


def _find_domains_and_ips_in_text(text) -> str:
    ipv4 = REGEX_IPV4.search(text)
    if ipv4:
        return text[ipv4.start():ipv4.end()]

    ipv6 = REGEX_IPV6.search(text)
    if ipv6:
        return text[ipv6.start():ipv6.end()]

    urn = REGEX_URN.search(text)
    if urn:
        return text[urn.start():urn.end()]

    return ""


def _find_password_in_text(text):
    for k in PASSWORD_KEYWORDS:
        if k in text:
            return True
    return False


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def search_in_metadata(image_info: DockerImageInfo,
                       results: DockerImageAnalysisResults):
    """
    Search sensitive information in metadata:

    - Passwords in environments vars
    - Detect root user running
    - Excessive port exposed
    """

    # Try to find passwords in vars environments
    for env in image_info.environment:
        if _find_password_in_text(env):
            results.add_sensitive(DockerImageAnalysisResults.PASSWORD,
                                  "environment_var",
                                  env)

        urn = _find_domains_and_ips_in_text(env)
        if urn:
            results.add_sensitive(DockerImageAnalysisResults.URN,
                                  "environment_var",
                                  urn)

    # Try to check if root is running as root
    if image_info.user:
        results.add_user(image_info.user)

    # Many ports exposed?
    if len(image_info.exposed_ports) > 4:
        results.add_warning("exposed_ports",
                            "Docker image has more thant 4 ports are exposed")


def search_in_content(image_location: str,
                      image_metadata: DockerImageInfo,
                      results: DockerImageAnalysisResults):

    start_point = _build_start_point(image_metadata)

    user = _find_user_in_start_point(image_location,
                                     start_point,
                                     image_metadata)

    results.add_user(user)


def analyze_docker_image(image_extracted_location: str,
                         image_info: DockerImageInfo) -> \
        DockerImageAnalysisResults:

    results = DockerImageAnalysisResults()

    # Search in metadata
    search_in_metadata(image_info, results)

    # Search in content
    search_in_content(image_extracted_location,
                      image_info,
                      results)

    return results


__all__ = ("analyze_docker_image", "search_in_content", "search_in_metadata")

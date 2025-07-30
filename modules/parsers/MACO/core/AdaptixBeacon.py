from cape_parsers.CAPE.core.AdaptixBeacon import extract_config
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    parsed_result = MACOModel(family="AdaptixBeacon", other=raw_config)
    # handle telegram
    if raw_config.get("C2"):
        # URL related to C2
        parsed_result.http.append(MACOModel.Http(uri=raw_config["C2"], usage="c2"))
    
    # encryption
    if raw_config["config_rc4_key"]:
        parsed_result.encryption.append(MACOModel.Encryption(
            algorithm='RC4',
            key=raw_config["config_rc4_key"]
        ))
    # servers
    for server in raw_config["servers"]:
        parsed_result.http.append(MACOModel.Http(hostname=server,
                                                 method=parsed_result["http_method"],
                                                 headers=parsed_result["http_headers"],
                                                 user_agent=parsed_result["user_agent"],
                                                 uri=parsed_result["uri"],
                                                 usage="c2"))
    # sleep delay / jitter
    if parsed_result["sleep_delay"]:
        parsed_result.sleep_delay = parsed_result["sleep_delay"]
    if parsed_result["jitter_delay"]:
        parsed_result.sleep_delay_jitter = parsed_result["jitter_delay"]
    
    return parsed_result

'''
    config["config_rc4_key"] = rc4_key.hex()
    config["agent_type"] = f"{read('<I'):8X}"
    config["use_ssl"] = read("<B")
    host_count = read("<I")
    for host in range(host_count):
        host_length = read("<I")
        servers.append(read_str(host_length).strip("\x00"))
        ports.append(read("<I"))

    config["servers"] = servers
    config["ports"] = ports
    method_length = read("<I")
    config["http_method"] = read_str(method_length).strip("\x00")
    uri_length = read("<I")
    config["uri"] = read_str(uri_length).strip("\x00")
    parameter_length = read("<I")
    config["parameter"] = read_str(parameter_length).strip("\x00")
    useragent_length = read("<I")
    config["user_agent"] = read_str(useragent_length).strip("\x00")
    headers_length = read("<I")
    config["http_headers"] = read_str(headers_length).strip("\x00")
    config["ans_pre_size"] = read("<I")
    config["ans_size"] = read("<I")
    config["kill_date"] = read("<I")
    config["working_time"] = read("<I")
    config["sleep_delay"] = read("<I")
    config["jitter_delay"] = read("<I")

    return config
'''


class AdaptixBeacon(Extractor):
    author = "kevoreilly"
    family = "AdaptixBeacon"
    last_modified = "2025-07-30"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))

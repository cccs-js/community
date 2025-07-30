from cape_parsers.CAPE.community.Arkei import extract_config
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule

# Hash = 69ba4e2995d6b11bb319d7373d150560ea295c02773fe5aa9c729bfd2c334e1e

RULE_SOURCE = """rule Arkei
{
    meta:
        author = "Yung Binary"
        reference = "https://github.com/CAPESandbox/CAPE-parsers/blob/main/cape_parsers/CAPE/community/Arkei.py"
    strings:
        $decode_1 = {
            6A ??
            68 ?? ?? ?? ??
            68 ?? ?? ?? ??
            E8 ?? ?? ?? ??
        }
        $decode_2 = {
            6A ??
            68 ?? ?? ?? ??
            68 ?? ?? ?? ??
            [0-5]
            E8 ?? ?? ?? ??
        }
    condition:
        any of them
}"""

def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    parsed_result = MACOModel(family="Arkei", other=raw_config)
    if raw_config.get("C2"):
        # URL related to C2
        parsed_result.http.append(MACOModel.Http(uri=raw_config["C2"], usage="c2"))
    if raw_config.get("Botnet ID"):
        parsed_result.campaign_id.append(raw_config.get("Botnet ID"))
    return parsed_result


class Arkei(Extractor):
    author = "kevoreilly"
    family = "Arkei"
    last_modified = "2025-07-30"
    sharing = "TLP:CLEAR"
    yara_rule = RULE_SOURCE

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))

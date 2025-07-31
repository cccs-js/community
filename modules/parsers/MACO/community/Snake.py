from cape_parsers.CAPE.community.Snake import extract_config
from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.parsers.utils import get_YARA_rule


def convert_to_MACO(raw_config: dict):
    if not (raw_config and isinstance(raw_config, dict)):
        return None

    parsed_result = MACOModel(family="Snake", other=raw_config)
    # handle telegram
    if raw_config["Type"] == 'Telegram':
        # URL related to C2
        parsed_result.http.append(MACOModel.Http(uri=raw_config["C2"], usage="c2"))
    
    # handle smtp
    if raw_config["Type"] == 'SMTP':
        parsed_result.smtp.append(MACOModel.SMTP(
            hostname=raw_config["Host"],
            port=raw_config["Port"],
            password=raw_config["Password"],
            mail_to=[raw_config["To Address"]],
            mail_from=raw_config["From Address"],
            usage="c2"
        )
        )
    return parsed_result

class Snake(Extractor):
    author = "kevoreilly"
    family = "Snake"
    last_modified = "2025-07-31"
    sharing = "TLP:CLEAR"
    yara_rule = get_YARA_rule(family)

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))

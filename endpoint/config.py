"""配置只存在端点私有目录；令牌不经命令行传递。"""
import json
import os
from pathlib import Path
from urllib.parse import urlparse


def load():
    path = Path(os.environ.get('ASGP_ENDPOINT_CONFIG', str(Path.home()/'.asgp/endpoint/config.json')))
    data = json.loads(path.read_text())
    url = urlparse(data['server_base_url'])
    if url.scheme != 'https' and not (url.scheme == 'http' and url.hostname in ('127.0.0.1', 'localhost', '::1')):
        raise ValueError('HTTPS required except loopback SSH tunnel')
    data.setdefault('state_dir', str(path.parent))
    data.setdefault('fail_mode', 'observe')
    return data

import runpy
import xml.etree.ElementTree as ET
from pathlib import Path


def test_generated_decoy(tmp_path):
    script = Path(__file__).resolve().parents[1] / 'roles/https_proxy/files/generate-decoy.py'
    generate = runpy.run_path(str(script))['generate']
    generate(tmp_path)
    html = (tmp_path / 'index.html').read_text()
    assert 'content="noindex,nofollow"' in html
    assert '<h1>' in html and 'src="/art.svg"' in html
    assert (tmp_path / 'robots.txt').read_text() == 'User-agent: *\nDisallow: /\n'
    image = ET.parse(tmp_path / 'art.svg').getroot()
    assert len(image.findall('{http://www.w3.org/2000/svg}circle')) == 18

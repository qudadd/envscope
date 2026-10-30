"""Generate offline region presets from a pinned Unicode CLDR release (no runtime fetch)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
from urllib.request import urlopen
import xml.etree.ElementTree as ET

REVISION = 'acd6d88ae493633240e19a87a721076a8a75c310'  # CLDR release-48
BASE = f'https://raw.githubusercontent.com/unicode-org/cldr/{REVISION}/'
FILES = ('common/supplemental/windowsZones.xml', 'common/supplemental/likelySubtags.xml',
         'common/main/zh.xml', 'common/bcp47/timezone.xml', 'LICENSE')
EXPECTED_SHA256 = dict(zip(FILES, (
    '9cf3db6a31fb382fee21b70be6feba1e82766b0fcd06e6261fb7936a73e537ff',
    'd7732172848cc2870d0d316818190e704bc6614486168dc52af56ee1427b6860',
    'b1ef8bcadcf19fa8914d9ba812a7bcec124c72fecbf4acea02e4c8bd2fe51866',
    '54ce7d9f1d385101e24356df7d48ae62cf2acc4421378da60a4007d2488c1aad',
    'b4c0ae8ef04f7059f96ce5bbe0467f9fe6f6d81bbe13517701dfeb961fb4d0b6',
)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    args.cache.mkdir(parents=True, exist_ok=True)
    sources, digests = {}, {}
    for name in FILES:
        cached = args.cache / name.replace('/', '_')
        if not cached.exists():
            with urlopen(BASE + name, timeout=30) as response:
                cached.write_bytes(response.read(4_000_000))
        content = cached.read_bytes()
        sources[name] = content
        digests[name] = hashlib.sha256(content).hexdigest()
        if digests[name] != EXPECTED_SHA256[name]:
            raise ValueError('Pinned CLDR source digest mismatch: ' + name)
    zh = ET.fromstring(sources['common/main/zh.xml'])
    names = {n.attrib['type']: n.text for n in zh.findall('./localeDisplayNames/territories/territory')
             if re.fullmatch('[A-Z]{2}', n.attrib['type']) and not n.attrib.get('alt')
             and n.attrib['type'] not in ('ZZ', 'QO', 'EU', 'EZ', 'UN', 'XA', 'XB')}
    # Region naming is presentation only, independent of the product availability list.
    names.update(CN='中国大陆', HK='中国香港', MO='中国澳门', TW='中国台湾')
    cities = {n.attrib['type']: n.findtext('exemplarCity') for n in zh.findall('./dates/timeZoneNames/zone')}
    likely = {n.attrib['from']: n.attrib['to'] for n in
              ET.fromstring(sources['common/supplemental/likelySubtags.xml']).iter('likelySubtag')}
    aliases = {}
    for node in ET.fromstring(sources['common/bcp47/timezone.xml']).iter('type'):
        zones = node.attrib.get('alias', '').split()
        if zones:
            for zone in zones:
                aliases[zone] = tuple(zones)
    windows = ET.fromstring(sources['common/supplemental/windowsZones.xml'])
    rows = []
    for node in windows.iter('mapZone'):
        country = node.attrib['territory']
        if country not in names:
            continue
        language = likely.get('und_' + country, '').split('_')[0]
        for zone in node.attrib['type'].split():
            city = cities.get(zone) or next((cities[a] for a in aliases.get(zone, ()) if cities.get(a)), None)
            city = city or zone.rsplit('/', 1)[-1].replace('_', ' ')
            key = country.lower() + '-' + re.sub('[^a-z0-9]+', '-', zone.lower()).strip('-')
            locale = language + '-' + country if language else ''
            rows.append((key, names[country] + ' · ' + city, country, zone,
                         node.attrib['other'], locale, aliases.get(zone, (zone,))))
    rows.sort(key=lambda row: (row[2], row[3]))
    content = ('"""Generated CLDR 48 region data. Unicode-3.0; see licenses/Unicode-3.0.txt.\n'
               'Regenerate using scripts/generate_region_data.py. Preferences, not location evidence.\n"""\n\n'
               f'CLDR_REVISION = {REVISION!r}\n'
               f'SOURCE_SHA256 = {digests!r}\n\nCOUNTRIES = (\n' +
               ''.join('    ' + repr((code, name)) + ',\n' for code, name in sorted(names.items())) +
               ')\n\nREGIONS = (\n' + ''.join('    ' + repr(row) + ',\n' for row in rows) + ')\n')
    (root / 'envscope/region_data.py').write_text(content, encoding='utf-8', newline='\n')
    (root / 'licenses').mkdir(exist_ok=True)
    (root / 'licenses/Unicode-3.0.txt').write_bytes(sources['LICENSE'])
    print(json.dumps({'countries': len(names), 'presets': len(rows),
                      'countries_with_presets': len({r[2] for r in rows}), 'revision': REVISION}))


if __name__ == '__main__':
    main()

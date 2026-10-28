"""Explicit city presets; these are preferences, never proof of location."""

PROFILES = (
    ('us-los-angeles', '美国 · 洛杉矶', 'US', 'America/Los_Angeles', 'Pacific Standard Time', 'en-US'),
    ('us-new-york', '美国 · 纽约', 'US', 'America/New_York', 'Eastern Standard Time', 'en-US'),
    ('us-chicago', '美国 · 芝加哥', 'US', 'America/Chicago', 'Central Standard Time', 'en-US'),
    ('us-denver', '美国 · 丹佛', 'US', 'America/Denver', 'Mountain Standard Time', 'en-US'),
    ('jp-tokyo', '日本 · 东京', 'JP', 'Asia/Tokyo', 'Tokyo Standard Time', 'ja-JP'),
    ('sg-singapore', '新加坡', 'SG', 'Asia/Singapore', 'Singapore Standard Time', 'en-SG'),
    ('tw-taipei', '中国台湾 · 台北', 'TW', 'Asia/Taipei', 'Taipei Standard Time', 'zh-TW'),
    ('gb-london', '英国 · 伦敦', 'GB', 'Europe/London', 'GMT Standard Time', 'en-GB'),
    ('de-berlin', '德国 · 柏林', 'DE', 'Europe/Berlin', 'W. Europe Standard Time', 'de-DE'),
    ('fr-paris', '法国 · 巴黎', 'FR', 'Europe/Paris', 'Romance Standard Time', 'fr-FR'),
    ('kr-seoul', '韩国 · 首尔', 'KR', 'Asia/Seoul', 'Korea Standard Time', 'ko-KR'),
    ('ca-toronto', '加拿大 · 多伦多', 'CA', 'America/Toronto', 'Eastern Standard Time', 'en-CA'),
    ('ca-vancouver', '加拿大 · 温哥华', 'CA', 'America/Vancouver', 'Pacific Standard Time', 'en-CA'),
    ('au-sydney', '澳大利亚 · 悉尼', 'AU', 'Australia/Sydney', 'AUS Eastern Standard Time', 'en-AU'),
    ('au-perth', '澳大利亚 · 珀斯', 'AU', 'Australia/Perth', 'W. Australia Standard Time', 'en-AU'),
)


def profiles(system):
    return [dict(id=key, label=label, country=country, timezone=windows if system == 'Windows' else iana,
                 locale=locale if system == 'Windows' else locale.replace('-', '_'), iana=iana)
            for key, label, country, iana, windows, locale in PROFILES]


def profile(key, system):
    return next((p for p in profiles(system) if p['id'] == key), None)


def validate_profile(values):
    key = values.get('region_profile', '')
    if not isinstance(key, str) or key and not any(row[0] == key for row in PROFILES):
        raise ValueError('请选择已支持的地区与城市，或使用自定义比较目标')
    if key:
        choices = [profile(key, system) for system in ('Windows', 'Darwin')]
        if not any(all(str(values.get(k, '')).replace('_', '-').lower() == str(p[k]).replace('_', '-').lower()
                       for k in ('country', 'timezone', 'locale')) for p in choices):
            raise ValueError('地区预设与目标值不一致，请重新选择城市；自行填写时改选自定义')

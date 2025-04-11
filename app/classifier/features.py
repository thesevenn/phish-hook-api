from urllib.parse import urlparse
import re
import pandas as pd

class Features:
    @staticmethod
    def extract_url_features(url: str) -> pd.DataFrame:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''

        features = dict()

        # 1. UsingIP
        features['UsingIP'] = 1 if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', hostname) else 0

        # 2. LongURL (thresholds can be adjusted)
        features['LongURL'] = 1 if len(url) >= 75 else 0

        # 3. ShortURL (opposite of long, or check known shortening services)
        features['ShortURL'] = 1 if len(url) < 25 or any(short in url for short in [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd'
        ]) else 0

        # 4. Symbol@
        features['Symbol@'] = 1 if '@' in url else 0

        # 5. Redirecting//
        # More than one '//' after protocol
        features['Redirecting//'] = 1 if url.count('//') > 1 else 0

        # 6. PrefixSuffix- (e.g. http://www.paypal-security.com)
        features['PrefixSuffix-'] = 1 if '-' in hostname else 0

        # 7. SubDomains (heuristic: more than 3 dots means suspicious)
        dot_count = hostname.count('.')
        features['SubDomains'] = 1 if dot_count > 3 else 0

        # 8. HTTPS
        features['HTTPS'] = 1 if parsed.scheme == 'https' else 0

        # 9. HTTPSDomainURL — misleading if it uses https in domain (e.g. "https-secure-login.com")
        features['HTTPSDomainURL'] = 1 if 'https' in hostname.replace('https://', '') else 0

        selected_features = [
            'UsingIP',
            'LongURL',
            'ShortURL',
            'Symbol@',
            'Redirecting//',
            'PrefixSuffix-',
            'SubDomains',
            'HTTPS',
            'HTTPSDomainURL'
        ]
        input_df = pd.DataFrame([features], columns=selected_features)

        return input_df
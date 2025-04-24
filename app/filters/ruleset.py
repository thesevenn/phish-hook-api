import re
import whois
import tldextract
import urllib.parse
from typing import List
from datetime import datetime
from bs4 import BeautifulSoup
from rapidfuzz import fuzz, process

from app.config.store import Store
from app.config.utils import Utils
from app.config.consts import Consts
from app.scores.risk import RiskScore


class Ruleset:
    """
    Rulesets define the rules used to flag email features( subject, sender, body, urls )
    as phishing or legitimate. Rulesets provide rules to the Filters to build threat score for a feature
    """

    @staticmethod
    def check_domain_spoofing(sender_domain: str):
        domain = sender_domain.strip().lower()

        brands = Store.trusted_brands # list of known brands
        sender_brand:str = Utils.extract_brand(domain) # extract brand name
        tld:str = Utils.extract_tld(domain)
        tokens:List[str] = Utils.extract_tokens(domain)

        # reduce the search area by pre-filtering
        search_space: List[str] = [
            str(brand) for brand in brands
            if len(brand) > 2 and (abs(len(brand) - len(sender_brand)) <= 2 or abs(len(tokens[0]) - len(brand)) <= 2)
               and brand[0] == sender_brand[0]
        ]

        if sender_brand in search_space:
            return RiskScore.empty()

        primary_token = tokens[0] if tokens else sender_brand # likely brand name
        combined_token = ''.join(tokens) if len(tokens) >=2 else primary_token

        match, score, pos = process.extractOne(primary_token, search_space, scorer=fuzz.token_sort_ratio,
                                               score_cutoff=75)

        risk_factors = ""
        risk_score = 0

        if score == 100 and match == primary_token:
            if tld != Store.brand_tld[pos]:
                risk_score = Consts.SEVERE
                risk_factors = f"{sender_domain} might be spoofing {match}"

        if score >= 85:
            risk_score = Consts.HIGH
            risk_factors= f"{sender_domain} might be spoofing {match}"

            # if not enough score look for combination
        if not match or score < 80:
            # fallback to combined token
            match, score, _ = process.extractOne(combined_token, search_space, scorer=fuzz.token_sort_ratio)
            if score > 82:
                risk_score = Consts.HIGH
                risk_factors= f"{sender_domain} might be spoofing {match}"

        # checks again with lowered threshold - scores nominally
        if score > 82:
            risk_score = Consts.MODERATE
            risk_factors= f"{sender_domain} might be spoofing {match}"

        return RiskScore("domain_spoofing",
                         risk_score,
                         [risk_factors],
                         "Possible domain spoofing: {}").to_dict() if risk_score > 0 else RiskScore.empty()

    @staticmethod
    def check_suspicious_language(target_text: str):
        risk_score = 0
        risk_factors = []
        content = target_text.lower()

        # phrases
        for phrase in Store.phishing_phrases:
            if phrase in content:
                risk_score += Consts.MODERATE
                risk_factors.append(phrase)
                content = content.replace(phrase, '')  # Remove to avoid re-hit

        # patterns
        for pattern, label in Store.phishing_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                risk_score += Consts.MODERATE
                risk_factors.append(f"{label}:{','.join(matches)}")
                for match in matches:
                    content = content.replace(match.lower(), '')  # Remove each match

        # keywords (only if previous steps didn't trigger)
        if risk_score == 0:
            for keyword in Store.phishing_keywords:
                if keyword in content:
                    risk_score += Consts.LOW
                    risk_factors.append(f"keyword(s) - {keyword}")
                    content = content.replace(keyword, '')  # Again, clean after match

        return RiskScore("suspicious_language",
                         risk_score,
                         risk_factors,
                         "Deceptive and manipulative language: {}").to_dict() if risk_score > 0 else RiskScore.empty()

    # Check domains age - <= 30 days possible phishing
    @staticmethod
    def check_domain_age(domain: str):
        risk_score = 0
        risk_factor = []
        try:
            if domain and '.' in domain:
                domain_whois_details = whois.whois(domain)
                if not domain_whois_details.domain_name:
                    risk_score += Consts.MODERATE
                    risk_factor.append(f"{domain} - No record found( Might not be registered )")
                elif domain_whois_details.creation_date is not None:
                    creation_date = domain_whois_details.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    domain_age = (datetime.now() - creation_date).days
                    if domain_age <= 30:
                        risk_score += Consts.HIGH
                        risk_factor.append(
                            f"{domain} created on {creation_date.strftime('%Y-%m-%d')}")
                else:
                    risk_score += Consts.MODERATE
                    risk_factor.append(f"{domain} - No registration date found")

        except whois.parser.PywhoisError:
            print("Domain not found (might not be registered)")
            risk_score += Consts.MODERATE
            risk_factor.append(f"WHOIS lookup failed — domain not found: {domain}")
        except TimeoutError:
            print("WHOIS Request timed out, TRY AGAIN")
            risk_score += Consts.MODERATE
            risk_factor.append(f"WHOIS timeout — cannot verify {domain}")
        except ConnectionError:
            print("Connection to WHOIS server cannot be made(Server down)")
            risk_score += Consts.MODERATE
            risk_factor.append(f"WHOIS server not reachable — cannot verify {domain}")
        except Exception as e:
            print(f"Unexpected error-{e}")
            risk_score += Consts.LOW
            risk_factor.append("Unexpected error domain age check failed")

        return RiskScore("domain_age",
                         risk_score,
                         risk_factor).to_dict() if risk_score > 0 else RiskScore.empty()

    @staticmethod
    def extract_urls(content_html="", content_text=""):
        parser = BeautifulSoup(content_html, 'html.parser')
        urls_from_html = [a['href'] for a in parser.find_all('a', href=True)]
        url_re = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
        urls_from_text = re.findall(url_re, content_text)
        return set(urls_from_text + urls_from_html)

    @staticmethod
    def check_brand_impersonation(domain: str, target_text: str):
        brand = Utils.extract_brand(domain).lower()
        primary_token = Utils.extract_tokens(brand)[0]
        targeted_brands = Store.trusted_brands
        risk_score = 0
        risk_factors = []
        highest_match = 0
        search_space = [ target.lower() for target in targeted_brands if len(target) > 2 and target[0] == brand[0]]
        target_text = target_text.lower()
        for target in search_space:
            if target in target_text and target not in brand:
                match = fuzz.ratio(target,primary_token)
                if match > highest_match and primary_token != target:
                    highest_match = match
                    risk_score = Consts.CRITICAL
                    risk_factors.append(target)
        return RiskScore("brand_impersonation",
                         min(risk_score,Consts.CRITICAL),
                         risk_factors,
                         "Possible brand impersonation of: {}").to_dict() if risk_score > 0 else RiskScore.empty()

    @staticmethod
    def check_url_redirects(urls: List[str] = None):
        shortener_domains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
        risk_score = 0
        flagged_urls = []
        for url in urls:
            parsed_url = urllib.parse.urlparse(url)
            if any(domain == (Ruleset.url_domain(url)) for domain in shortener_domains):
                risk_score += Consts.LOW
                flagged_urls.append(url)
            query_parameters = urllib.parse.parse_qs(parsed_url.query)
            redirect_params = ['url', 'link', 'redirect', 'goto', 'return', 'returnurl']
            if any(params in query_parameters for params in redirect_params):
                risk_score += Consts.HIGH
                flagged_urls.append(url)

        return RiskScore("url_redirects",
                         risk_score,
                         flagged_urls,
                         "Redirections found: {}").to_dict() if risk_score > 0 else RiskScore.empty()

    @staticmethod
    def check_exclamations(target_text: str):
        excl_re = r'!{2,}'
        matches = re.findall(excl_re, target_text.lower().replace("\n", " "))

        return RiskScore("exclamations",
                         Consts.LOW,
                         [f"{','.join([word for word in set(matches)])} exclamation marks found"],
                         "Attention(!!!) indicators: {}").to_dict() if len(matches) >= 1 else RiskScore.empty()

    @staticmethod
    def check_ip_as_url(url: str):
        ip_url_re = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        match = re.fullmatch(ip_url_re, url)
        return RiskScore("ip_url",
                         Consts.CRITICAL,
                         [url],
                         "IP address as URL(s) found: {}").to_dict() if match else RiskScore.empty()

    @staticmethod
    def url_domain(url: str):
        return tldextract.extract(url).registered_domain

    @staticmethod
    def check_uppercase(target_text: str):
        """
        Low risk rule, checks uppercase words present in content.
        >= 3 count triggers the Rule
        Args:
            target_text:

        Returns:
            RiskScore object as dict
        """
        word_list = target_text.split(" ")
        isupper_count = 0

        for word in word_list:
            if word.isupper():
                isupper_count += 1
                if isupper_count >= 3:
                    return RiskScore("uppercase",
                                     min(isupper_count, 7),
                                     [f"Found {isupper_count} Uppercase words"]).to_dict()
        return RiskScore.empty()

    @staticmethod
    def check_reply_to(reply_to_domain, sender_domain):
        return RiskScore("reply_to",
                         Consts.MODERATE,
                         [f"Reply-to domain = {reply_to_domain}", f"Sender domain = {sender_domain}"],
                         "Domain difference: {}").to_dict() if reply_to_domain and reply_to_domain != sender_domain else RiskScore.empty()

    @staticmethod
    def check_url_blacklist(urls:List[str]):
        bloom_filter = Store.url_bloom_filter
        # go through each url get host, root, exact and match with blacklist
        # in list put result
        risk_score = 0
        risk_factor = []
        for url in urls:
            if url in bloom_filter:
                risk_score = Consts.CRITICAL
                risk_factor.append(url)

        return RiskScore("url_black_list",
                         risk_score,
                         risk_factor,
                         "Malicious urls found: {}").to_dict() if risk_score > 0 else RiskScore.empty()


    # TODO
    @staticmethod
    def check_spf():
        pass

    # TODO
    @staticmethod
    def check_tld_rank():
        pass

    # TODO
    @staticmethod
    def check_tls():
        pass

    # TODO
    @staticmethod
    def check_url_mismatches():
        pass

    # TODO
    def check_redirection_chain(self):
        pass

    # TODO - Add RiskScore
    # TODO - check if sender display name is different from the email
    # example - Apple Support <random-tech@gmail.com>
    # domain(gmail.com) or address(random-tech) does not match with <Apple Support>
    @staticmethod
    def check_suspicious_sender(sender_domain: str):
        risk_score = 0
        risk_factors = []

        ip_pattern = r"^\[?\d{1,3}(\.\d{1,3}){3}\]?$"
        if re.match(ip_pattern, sender_domain):
            risk_score += Consts.HIGH
            risk_factors.append(f"Sender domain is an IP address: {sender_domain}")
        elif sender_domain in ['localhost', 'localdomain'] or '.' not in sender_domain:
            risk_score += Consts.MODERATE
            risk_factors.append(f"Suspicious sender domain format: {sender_domain}")

    # TODO - check name present and not any generic Hello customer
    # TODO - Compare domain/email/url with a blacklist


if __name__ == "__main__":
    import time
    start = time.time()
    print(Ruleset.check_domain_spoofing("google.com"))
    print(time.time()-start)
    """
    1. Integrate Sender Reputation / Domain Whitelist
Add a lightweight check:

If sender_domain ∈ known trusted orgs (Microsoft, Google, banks) → reduce risk score only if DKIM/SPF pass

Bonus: Cross-check links → if link domain == sender domain → boost trust.

if sender_domain == "microsoft.com" and all_links_resolve_to("microsoft.com"):
    reduce_risk_score(10)
    """

"""
If you pass features like:

domain_match = True

spf_pass = True

sender_verified = True

Then ML could learn to downgrade risk even if urgency words appear.
"""

"""
The language "If this was you, ignore this message" is actually a de-phisher
phrase used by Microsoft and others to legitimize alerts.
That’s a contextual feature your system could eventually learn to reduce suspicion when present.
"""
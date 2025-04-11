from app.filters.ruleset import Ruleset
from app.scores.risk import RiskScore
from app.scores.threat import ThreatScore
from app.scores.builder import ThreatScoreBuilder

class RuleFilters:
    def __init__( self, features, builder: ThreatScoreBuilder ):
        self.__features = features
        if not isinstance(builder, ThreatScoreBuilder):
            raise TypeError("Invalid ThreatScoreBuilder instance")
        self.__builder = builder

    def runner(self):
        self.__builder.add_threat_score(self.analyze_sender())
        self.__builder.add_threat_score(self.analyze_subject())
        self.__builder.add_threat_score(self.analyze_body())
        self.__builder.add_threat_score(self.analyze_urls())

    # add SPF check score
    def analyze_sender(self):
        threat_score = 0
        threat_clues = []
        threat_factors = []
        display_name, sender_email, sender_domain = self.__features["sender"]
        _,_, reply_to_domain = self.__features["reply_to"]
        scores = [Ruleset.check_domain_spoofing(sender_domain=sender_domain),
                  Ruleset.check_reply_to(reply_to_domain=reply_to_domain, sender_domain=sender_domain),
                  Ruleset.check_domain_age(domain=sender_domain)]
        if sender_domain != reply_to_domain:
            scores.append(Ruleset.check_domain_age(domain=reply_to_domain))
        for score in scores:
            if score:
                threat_score += RiskScore.extract_score(score_as_dict=score,
                                                        threat_clues=threat_clues,
                                                        threat_factors=threat_factors)

        return ThreatScore(threat_name="sender",
                           threat_score=threat_score,
                           original_value=f"{display_name},<{sender_email}>",
                           analysis_type="filter",
                           threat_factors=threat_factors,
                           threat_clues=threat_clues) if threat_score > 0 else ThreatScore.empty()

    # uppercase, !! and sus lang check score
    def analyze_subject(self):
        threat_score = 0
        threat_clues = []
        threat_factors = []
        subject = self.__features["subject"]
        scores = [Ruleset.check_uppercase(target_text=subject),
                  Ruleset.check_exclamations(target_text=subject),
                  Ruleset.check_suspicious_language(target_text=subject)]

        for score in scores:
            if score:
                threat_score += RiskScore.extract_score(score_as_dict=score,
                                                        threat_clues=threat_clues,
                                                        threat_factors=threat_factors)

        return ThreatScore(threat_name="subject",
                           threat_score=threat_score,
                           original_value=subject,
                           analysis_type="filter",
                           threat_factors=threat_factors,
                           threat_clues=threat_clues) if threat_score > 0 else ThreatScore.empty()

    # uppercase, !!, impersonation, script, form tag in html and sus lang check score
    def analyze_body(self):
        threat_score = 0
        threat_clues = []
        threat_factors = []
        body_text = self.__features["body_text"]
        body_html = self.__features["body_html"]
        _,_,sender_domain = self.__features["sender"]
        scores = [Ruleset.check_uppercase(target_text=body_text),
                  Ruleset.check_exclamations(target_text=body_text),
                  Ruleset.check_brand_impersonation(target_text=body_text,domain=sender_domain),
                  Ruleset.check_suspicious_language(target_text=body_text)]
        for score in scores:
            if score:
                threat_score += RiskScore.extract_score(score_as_dict=score,
                                                        threat_clues=threat_clues,
                                                        threat_factors=threat_factors)

        return ThreatScore(threat_name="body",
                           threat_score=threat_score,
                           original_value=body_text,
                           analysis_type="filter",
                           threat_factors=threat_factors,
                           threat_clues=threat_clues) if threat_score > 0 else ThreatScore.empty()

    # domain age, domain spoofing, label matching, ip url,
    # tld rank, redirection chain and url redirects check score
    def analyze_urls(self):
        threat_score = 0
        threat_clues = []
        threat_factors = []
        body_html = self.__features["body_html"]
        body_text = self.__features["body_text"]
        _,_, sender_domain = self.__features["sender"]
        urls = Ruleset.extract_urls(content_html=body_html, content_text=body_text)
        scores = [Ruleset.check_url_redirects(urls)]
        domains = set(Ruleset.url_domain(url) for url in urls)

        for domain in domains:
            scores.append(Ruleset.check_domain_spoofing(domain))
            scores.append(Ruleset.check_brand_impersonation(domain, body_text))
            if domain != sender_domain:
                scores.append(Ruleset.check_domain_age(domain))

        for url in urls:
            scores.append(Ruleset.check_ip_as_url(url))

        for score in scores:
            if score:
                threat_score += RiskScore.extract_score(score_as_dict=score,
                                                        threat_clues=threat_clues,
                                                        threat_factors=threat_factors)

        return ThreatScore(threat_name="urls",
                           threat_score=threat_score,
                           original_value=urls,
                           analysis_type="filter",
                           threat_factors=threat_factors,
                           threat_clues=threat_clues) if threat_score > 0 else ThreatScore.empty()


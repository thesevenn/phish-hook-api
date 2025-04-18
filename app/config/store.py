import logging
class Store:
    logger = logging.getLogger("uvicorn.error")
    phishing_phrases = [
    # Account security
    "verify your account",
    "suspicious login attempt",
    "unusual activity detected",
    "unauthorized access",
    "your account has been compromised",
    "confirm your identity",
    "update your account information",
    "security alert from",
    "we noticed suspicious activity",

    # Threats & fear tactics
    "your account will be terminated",
    "account has been suspended",
    "your account is on hold",
    "limited access to your account",
    "immediate action required",
    "final notice before closure",

    # Rewards & scams
    "you have won a prize",
    "claim your gift card",
    "congratulations! you're a winner",
    "exclusive offer just for you",
    "you have been selected",

    # Financial fraud
    "unpaid invoice",
    "overdue payment",
    "problem with your payment method",
    "payment failed",
    "verify billing details",

    # Delivery scams
    "your package could not be delivered",
    "delivery attempt failed",
    "update shipping address",
    "track your amazon order",
    "your amazon delivery is on hold",

    # Crypto scams
    "double your bitcoin",
    "limited time crypto offer",
    "claim your airdrop",
    "crypto wallet recovery",
    "investment opportunity in crypto"
]

    phishing_keywords = [
    # Urgency
    "urgent", "immediate", "asap", "now", "instantly", "today", "quickly",

    # Threats
    "terminate", "termination", "cancel", "cancelled", "expire", "expired", "expiration", "deactivate", "disabled", "locked",

    # Security
    "verify", "validate", "confirm", "secure", "security", "unauthorized", "suspicious", "alert", "breach", "protection",

    # Account/Access
    "account", "login", "sign-in", "update", "access", "maintenance", "restricted", "suspend", "suspended",

    # Finance
    "payment", "invoice", "billing", "overdue", "credit", "debit", "charge", "transaction",

    # Rewards & giveaways
    "prize", "winner", "congratulations", "free", "gift", "bonus", "offer", "promotion",

    # Crypto
    "bitcoin", "crypto", "ethereum", "wallet", "airdrop", "blockchain", "nft", "token"
]

    phishing_patterns = {
    # Urgency & pressure
    r'\b(?:urgent|immediately|act fast|asap|now|today only|instantly|respond within 24 hours)\b': "Urgency language",

    # Threats & account lockdown
    r'\b(?:terminate(?:d|s|ion)?|deactivate(?:d|s)?|expire(?:d|s|ing)?|locked|restricted|suspend(?:ed)?)\b': "Account threat",

    # Payment & finance fraud
    r'\b(?:overdue|invoice|payment failed|verify billing|unauthorized charge|credit card declined)\b': "Payment fraud trigger",

    # Fake rewards
    r'\b(?:congratulations|winner|gift card|free reward|claim your prize|you have won)\b': "Scam reward bait",

    # Security alerts
    r'\b(?:security alert|verify your identity|unauthorized access|update your password|confirm your account)\b': "Fake security alert",

    # Delivery & order scams
    r'\b(?:your package|delivery failed|track your order|shipping issue|amazon order on hold)\b': "Fake delivery notification",

    # Crypto scams
    r'\b(?:bitcoin|crypto wallet|airdrop|investment opportunity|limited time crypto offer|double your bitcoin)\b': "Crypto bait",

    # Excessive punctuation
    r'!{3,}': "Suspicious excessive exclamation marks",

    # Action requests
    r'\b(?:click here|verify now|login here|confirm now|update your details|reset your password)\b': "Suspicious call to action"
}

    targeted_brands = ["amazon", "bing", "google", "facebook", "paypal", "amex", "twitter", "microsoft"]
    url_black_list = []
    trusted_domains = ["amazon.com", "bing.com", "google.com", "facebook.com", "paypal.com", "amex.com", "twitter.com", "microsoft.com"]

    @staticmethod
    def load_and_cache_data(filename:str, column:str):
        import pandas as pd
        if not filename.lower().endswith(".csv"):
            raise ValueError("Invalid file type, csv expected")
        if not column:
            raise ValueError("Column is required to build a cache")
        try:
            df = pd.read_csv(filename)
            if column not in df.columns:
                raise ValueError(f"Column '{column}' not found in csv")
            cache = set(df[column])
            return cache
        except ValueError as ve:
            Store.logger.error(f"Value Error: {ve}",exc_info=True)
            raise
        except FileNotFoundError:
            Store.logger.error(f"File not found: '{filename}'")
            raise
        except Exception as e:
            Store.logger.error(f"Unknown error while processing file: {filename}: {e}",exc_info=True)
            raise

    @staticmethod
    def load():
        Store.trusted_domains = Store.load_and_cache_data("./data/trusted_domains.csv","Domain")
        Store.url_black_list = Store.load_and_cache_data("./data/black_list.csv","url")

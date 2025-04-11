import joblib
import pandas as pd
import time
from features import Features
from app.config.utils import Utils

class Classifier:

    url_model = joblib.load("./models/url_classifier.pkl")
    email_model = joblib.load("./models/email_classifier.pkl")

    @staticmethod
    def classify_email(sender:str,subject:str,body:str):
        features = {'sender':Utils.extract_sender_domain(sender),'subject':subject,'body':body}
        row = pd.DataFrame([features])
        row['text'] = Utils.prepare_text(row)
        return Classifier.email_model.predict_proba(row['text'])

    @staticmethod
    def classify_url(url:str)->object:
        df = Features.extract_url_features(url)
        return Classifier.url_model.predict_proba(df)


if __name__ == "__main__":
    start = time.time()
    print(Classifier.classify_url("http://micros0ft-support-login.com/security"))
    print(Classifier.classify_email("Microsoft Security Team <security@micros0ft-support-login.com>",
                              "Urgent Account Alert",
                              "Your Microsoft account is under threat. Click here to secure it immediately."))

    end = time.time()
    print(f"Took {round((end - start) * 1000, 2)} ms")
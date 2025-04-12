import time
import joblib
import pandas as pd
from sklearn.exceptions import NotFittedError

from app.config.utils import Utils
from app.classifier.features import Features

class Classifier:
    def __init__(self,features):
        self.__features = features

    url_model = joblib.load("./app/classifier/models/url_classifier.pkl")
    email_model = joblib.load("./app/classifier/models/email_classifier.pkl")

    def classify(self):
        try:
            result = []
            sender = self.__features["sender"]
            subject = self.__features["subject"]
            body = self.__features["body_text"] if self.__features["body_text"] else self.__features["body_html"]
            urls = self.__features["urls"]

            proba_email = Classifier.classify_email(sender, subject, body)
            if len(proba_email):
                result.append({
                    "type":"ML/EMAIL",
                    "proba":proba_email,
                    "remarks":"Email classifier inference run"
                })
            proba_url = []
            for url in urls:
                proba_url = Classifier.classify_url(url)
                if proba_url[0][1] > 0.6:
                    break
            result.append({
                    "type":"ML/URL",
                    "proba":proba_url,
                    "remarks":"URL classifier inference run"
                })
            return result
        except Exception as e:
            print("Unknown error",e)
            return []



    @staticmethod
    def classify_email(sender:str,subject:str,body:str):
        try:
            features = {'sender': Utils.extract_sender_domain(sender), 'subject': subject, 'body': body}
            row = pd.DataFrame([features])

            # add 'text' column with prepared text = "domain + subject + body"
            row['text'] = Utils.prepare_text(row)
            return Classifier.email_model.predict_proba(row['text'])
        except (ValueError,TypeError) as e:
            print("Input format error:", e)
        except (NotFittedError, AttributeError) as e:
            print("Model state error:", e)
        except (EOFError, FileNotFoundError, OSError) as e:
            print("Model loading error:", e)
        except Exception as e:
            print("Unknown prediction error:", e)


    @staticmethod
    def classify_url(url:str):
        try:
            df = Features.extract_url_features(url)
            return Classifier.url_model.predict_proba(df)
        except (ValueError, TypeError) as e:
            print("Input format error:", e)
        except (NotFittedError, AttributeError) as e:
            print("Model state error:", e)
        except (EOFError, FileNotFoundError, OSError) as e:
            print("Model loading error:", e)
        except Exception as e:
            print("Unknown prediction error:", e)


if __name__ == "__main__":
    start = time.time()
    print(Classifier.classify_url("http://micros0ft-support-login.com/security"))
    print(Classifier.classify_email("Microsoft Security Team <security@micros0ft-support-login.com>",
                              "Urgent Account Alert",
                              "Your Microsoft account is under threat. Click here to secure it immediately."))

    end = time.time()
    print(f"Took {round((end - start) * 1000, 2)} ms")
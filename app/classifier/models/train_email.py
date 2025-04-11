import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.utils import resample
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

from app.config.utils import Utils

# df = load_and_clean_dataset()

# read dataset into pandas dataframe
df = pd.read_csv("dataset.csv")
print(df.head())
print(df.columns)

# ========== PREPROCESSING ==========

# prepare data
df['text'] = df.apply(Utils.prepare_text, axis=1)

# Balance the dataset (upsample class 0)
df_majority = df[df['label'] == 1]
df_minority = df[df['label'] == 0]

df_minority_upsampled = resample(
    df_minority,
    replace=True,
    n_samples=len(df_majority),
    random_state=42
)

df_balanced = pd.concat([df_majority, df_minority_upsampled])


if __name__ == "__main__":
    # ========== SPLIT AND TRAIN ==========

    X_train, X_test, y_train, y_test = train_test_split(
        df_balanced['text'],
        df_balanced['label'],
        test_size=0.2,
        stratify=df_balanced['label'],
        random_state=42
    )

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=3000, stop_words='english')),
        ('clf', RandomForestClassifier(n_estimators=100, class_weight='balanced', random_state=42))
    ])

    pipeline.fit(X_train, y_train)

    # ========== EVALUATE MODEL ==========

    y_pred = pipeline.predict(X_test)
    print("\n=== Classification Report ===")
    print(classification_report(y_test, y_pred))
    print("=== Confusion Matrix ===")
    print(confusion_matrix(y_test, y_pred))

    # save Model as pkl file
    # joblib.dump(pipeline, "email_classifier.pkl")
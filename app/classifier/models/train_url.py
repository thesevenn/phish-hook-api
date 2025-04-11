import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib

# df = load_and_clean_dataset()

# read dataset into pandas dataframe
df = pd.read_csv('dataset.csv')
print(df.columns)
print(df.head())
print(df.value_counts())

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

# Use only selected features and labels
X = df[selected_features]
y = df['class']  # -1: legitimate, 1: phishing

# Convert -1 to 0 for easier interpretation
y = y.replace({-1: 0})

# Split into training/test sets
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)


if __name__ == "__main__":
    # Train a Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        class_weight='balanced',
        random_state=42
    )
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    print("\n=== Classification Report ===")
    print(classification_report(y_test, y_pred))

    print("\n=== Confusion Matrix ===")
    print(confusion_matrix(y_test, y_pred))

    # AUC score (optional)
    y_proba = model.predict_proba(X_test)[:, 1]
    print("\nAUC Score:", roc_auc_score(y_test, y_proba))

    # joblib.dump(model, "url_classifier.pkl")
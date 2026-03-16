import pandas as pd
from sklearn.ensemble import IsolationForest

def detect_anomalies(df):

    model = IsolationForest(contamination=0.1)

    df["anomaly"] = model.fit_predict(df[["failed_logins"]])

    anomalies = df[df["anomaly"] == -1]

    return df, anomalies
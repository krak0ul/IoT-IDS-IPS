import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder

def cleanValues(df):
    df = df.drop_duplicates()

    # Replace 'INF' or '-INF' with NaN (if they exist)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    # Drop rows with NaN values
    df.dropna(inplace=True)

    return df

def label_encode(df):
    # Identify categorical features
    categorical_features = df.select_dtypes(include=['object']).columns

    # Apply label encoding
    label_encoders = {}
    for col in categorical_features:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col])
        label_encoders[col] = le

    return df
    

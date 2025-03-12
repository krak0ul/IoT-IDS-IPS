import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler


def cleanValues(df):
    df = df.copy()  # Ensure we're working on a copy

    df = df.drop_duplicates()

    # Replace 'INF' or '-INF' with NaN (if they exist)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    # Drop rows with NaN values
    df.dropna(inplace=True)

    return df

def labelEncode(df):
    # Identify categorical features
    categorical_features = df.select_dtypes(include=['object']).columns

    # Apply label encoding
    label_encoders = {}
    for col in categorical_features:
        le = LabelEncoder()
        
        df[col] = df[col].astype(str)   # Convert column values to strings to ensure uniformity
        df[col] = le.fit_transform(df[col])
        label_encoders[col] = le

    return df
    
def scaleFeatures(df):
    # Standardize numerical features
    scaler = StandardScaler()
    scaled_columns = df.columns
    df[scaled_columns] = scaler.fit_transform(df[scaled_columns])

    print("Feature scaling applied.")
    return df

def prepareData(df):
    df = cleanValues(df)
    df = labelEncode(df)
    df = scaleFeatures(df)
    return df
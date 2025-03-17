import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import StandardScaler


def cleanValues(df):
    df = df.copy()  # Ensure we're working on a copy

    # maybe we should drop duplicates to reduce workload ?
    # df = df.drop_duplicates()

    # Replace 'INF' or '-INF' with NaN (if they exist)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    # Drop rows with NaN values
    df.dropna(inplace=True)

    return df

def labelEncode(df):
    # Identify categorical features - select_type would lead to the wrong fields being encoded, I fixed this by encoding only the parameters that were encoded in the training model
    # categorical_features = df.select_dtypes(include=['object']).columns
    categorical_features =  ['http.request.method', 'http.referer', 'http.request.version', 'dns.qry.name.len', 'mqtt.conack.flags', 'mqtt.protoname', 'mqtt.topic']
    # print(f"Encoded features: {categorical_features.tolist()}")    # Apply label encoding
    
    # convert all numeric columns to an numeric datatype
    numeric_columns = df.drop(columns=categorical_features).columns
    df[numeric_columns] = df[numeric_columns].apply(pd.to_numeric, errors='coerce')
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
    scaled_columns = df.select_dtypes(include=[np.number]).columns
    df[scaled_columns] = scaler.fit_transform(df[scaled_columns])

    print("Feature scaling applied.")
    return df

def prepareData(df):
    df = cleanValues(df)
    print("values cleaned:")
    print(df)
    df = labelEncode(df)
    print("label encoded:")
    print(df)
    df = scaleFeatures(df)
    return df
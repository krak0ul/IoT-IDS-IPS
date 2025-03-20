import joblib
import pandas as pd
import numpy as np


def cleanValues(df):
    df = df.copy()  # Ensure we're working on a copy

    # maybe we should drop duplicates to reduce workload ?
    # df = df.drop_duplicates()

    # Replace 'INF' or '-INF' with NaN (if they exist)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    print("cleaning values: ")
    print(df)
    # Drop rows with NaN values
    df.dropna(inplace=True)
    return df

def import_encoder(encoder_pickle):
    try:
        model = joblib.load(encoder_pickle)
        return model
    except Exception as e:
        print(f"Error importing model: {e}")
        return None

def labelEncode(df, encoder):
    # Identify categorical features - select_type would lead to the wrong fields being encoded, I fixed this by encoding only the parameters that were encoded in the training model
    # categorical_features = df.select_dtypes(include=['object']).columns
    categorical_features =  ['http.request.method', 'http.referer', 'http.request.version', 'dns.qry.name.len', 'mqtt.conack.flags', 'mqtt.protoname', 'mqtt.topic']
    # print(f"Encoded features: {categorical_features.tolist()}")    # Apply label encoding
    
    # convert all numeric columns to an numeric datatype
    numeric_columns = df.drop(columns=categorical_features).columns
    df[numeric_columns] = df[numeric_columns].apply(pd.to_numeric, errors='coerce')

    label_encoders = {}
    for col in categorical_features:
        le = encoder
        
        df[col] = df[col].astype(str)   # Convert column values to strings to ensure uniformity
        df[col] = le.fit_transform(df[col])
        label_encoders[col] = le

    return df

def import_scaler(scaler_pickle):
    try:
        model = joblib.load(scaler_pickle)
        return model
    except Exception as e:
        print(f"Error importing model: {e}")
        return None

def scaleFeatures(df, scaler):
    # Standardize numerical features
    
    # scaled_columns = df.select_dtypes(include=[np.number]).columns
    scaled_columns = df.columns
    df[scaled_columns] = scaler.fit_transform(df[scaled_columns])

    print("Feature scaling applied.")
    return df

def prepareData(df, scaler, encoder):
    df = cleanValues(df)
    print("values cleaned:")
    print(df)
    df = labelEncode(df, encoder)
    print("label encoded:")
    print(df)
    df = scaleFeatures(df, scaler)
    return df
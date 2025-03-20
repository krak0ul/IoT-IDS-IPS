# dataHandling/dataPreparation.py
import pickle
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
import os

def import_scaler(scaler_pickle):
    """
    Import the fitted scaler from pickle file
    """
    try:
        with open(os.path.join('pickles', scaler_pickle), 'rb') as f:
            scaler = pickle.load(f)
        return scaler
    except Exception as e:
        print(f"Error importing scaler: {e}")
        return None

def import_encoder(encoder_pickle):
    """
    Import the fitted encoder from pickle file
    """
    try:
        with open(os.path.join('pickles', encoder_pickle), 'rb') as f:
            encoder = pickle.load(f)
        return encoder
    except Exception as e:
        print(f"Error importing encoder: {e}")
        return None

def prepareData(df, scaler, encoder):
    """
    Prepare the data for ML prediction by scaling numerical features
    and encoding categorical features
    """
    if df.empty:
        print("Warning: Empty DataFrame received for preparation")
        return df
    
    # Make a copy to avoid modifying the original
    df_prepared = df.copy()
    
    # Identify numerical and categorical columns
    numerical_cols = df_prepared.select_dtypes(include=['int64', 'float64']).columns.tolist()
    categorical_cols = df_prepared.select_dtypes(include=['object']).columns.tolist()
    
    # Handle missing values
    for col in numerical_cols:
        df_prepared[col] = df_prepared[col].fillna(0)
    
    for col in categorical_cols:
        df_prepared[col] = df_prepared[col].fillna('unknown')
    
    # Scale numerical features if we have any and the scaler is available
    if numerical_cols and scaler:
        # Apply the scaler on numerical features
        try:
            df_prepared[numerical_cols] = scaler.transform(df_prepared[numerical_cols])
        except Exception as e:
            print(f"Error scaling numerical features: {e}")
            # Fall back to standard scaling if the imported scaler fails
            temp_scaler = StandardScaler()
            df_prepared[numerical_cols] = temp_scaler.fit_transform(df_prepared[numerical_cols])
    
    # Encode categorical features if we have any and the encoder is available
    if categorical_cols and encoder:
        try:
            # Get the feature names the encoder was fitted on
            encoder_feature_names = encoder.get_feature_names_out(categorical_cols)
            
            # Apply one-hot encoding
            encoded_array = encoder.transform(df_prepared[categorical_cols])
            
            # Convert to DataFrame with proper column names
            encoded_df = pd.DataFrame(
                encoded_array.toarray(),
                columns=encoder_feature_names,
                index=df_prepared.index
            )
            
            # Drop original categorical columns and join encoded ones
            df_prepared = df_prepared.drop(columns=categorical_cols)
            df_prepared = pd.concat([df_prepared, encoded_df], axis=1)
            
        except Exception as e:
            print(f"Error encoding categorical features: {e}")
            print("Warning: Using original categorical features without encoding")
    
    return df_prepared
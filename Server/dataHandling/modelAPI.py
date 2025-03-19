# dataHandling/modelAPI.py
import pickle
import os
import numpy as np
import pandas as pd
import json

def import_model(model_pickle):
    """
    Import the trained ML model from pickle file
    """
    try:
        with open(os.path.join('pickles', model_pickle), 'rb') as f:
            model = pickle.load(f)
        return model
    except Exception as e:
        print(f"Error importing model: {e}")
        return None

def prediction(model, df):
    """
    Make predictions using the imported model
    Returns a dictionary with predictions and confidence scores
    """
    if model is None:
        print("Error: No model provided for prediction")
        return {"error": "No model available"}
    
    if df.empty:
        print("Warning: Empty DataFrame received for prediction")
        return {"error": "No data for prediction"}
    
    try:
        # Make prediction
        if hasattr(model, 'predict_proba'):
            # Get probability predictions
            probas = model.predict_proba(df)
            predictions = model.predict(df)
            
            # Create results dictionary
            results = {
                "predictions": predictions.tolist(),
                "probabilities": probas.tolist()
            }
            
            # Calculate confidence scores
            if len(probas[0]) > 1:  # Multi-class case
                confidence = np.max(probas, axis=1)
            else:  # Binary case
                confidence = probas[:, 1]
                
            results["confidence"] = confidence.tolist()
            
            # Determine if traffic is malicious based on predictions
            # Assuming 1 = malicious, 0 = benign (adjust as needed)
            results["is_malicious"] = (predictions == 1).tolist()
            
        else:
            # Models without probability support
            predictions = model.predict(df)
            results = {
                "predictions": predictions.tolist(),
                "is_malicious": (predictions == 1).tolist()
            }
        
        return results
        
    except Exception as e:
        print(f"Error during prediction: {e}")
        return {"error": f"Prediction failed: {str(e)}"}

def predict_and_respond(model, df):
    """
    Makes predictions and formats a response suitable for the packet forwarder
    """
    prediction_results = prediction(model, df)
    
    # Format response for the packet forwarder
    response = {
        "is_malicious": any(prediction_results.get("is_malicious", [])),
        "confidence": max(prediction_results.get("confidence", [0])) if "confidence" in prediction_results else 0,
        "reason": "Potential malicious traffic detected by ML model"
    }
    
    return json.dumps(response)
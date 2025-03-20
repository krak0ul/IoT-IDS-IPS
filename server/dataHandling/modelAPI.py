import joblib
import asyncio
# import xgboost
import pandas as pd

from dataHandling.featureExtract import extract_packet, format_raw_packet, pcap_to_raw
from dataHandling.dataPreparation import prepareData
from settings import FEATURES

def import_model(model_pickle):
    try:
        model = joblib.load(model_pickle)
        return model
    except Exception as e:
        print(f"Error importing model: {e}")
        return None

def prediction(model, df):
    pred = model.predict(df)
    counts = pd.Series(pred).value_counts()
    labels = ['Non-Attack', 'Attack']  # Assuming 0 = Non-Attack, 1 = Attack

    print("val count: ")
    print(counts)
    return pred

async def pkt_processing(pkt, scaler, encoder, model):
    packet = await asyncio.to_thread(format_raw_packet, pkt)
    print("packet formatted")
    # print(packet)

    df = extract_packet(packet, FEATURES)
    if df is None:
        return
    else:
        df = prepareData(df, scaler, encoder)
        print(df)
        
        results = prediction(model, df)
        print("prediction: " + str(results))
        return


# #               TODO - Trucs de thomas à explorer
# def prediction(model, df):
#     try:
#         # Make prediction
#         if hasattr(model, 'predict_proba'):
#             # Get probability predictions
#             probas = model.predict_proba(df)
#             predictions = model.predict(df)
            
#             # Create results dictionary
#             results = {
#                 "predictions": predictions.tolist(),
#                 "probabilities": probas.tolist()
#             }
            
#             # Calculate confidence scores
#             if len(probas[0]) > 1:  # Multi-class case
#                 confidence = np.max(probas, axis=1)
#             else:  # Binary case
#                 confidence = probas[:, 1]
                
#             results["confidence"] = confidence.tolist()
            
#             # Determine if traffic is malicious based on predictions
#             # Assuming 1 = malicious, 0 = benign (adjust as needed)
#             results["is_malicious"] = (predictions == 1).tolist()
            
#         else:
#             # Models without probability support
#             predictions = model.predict(df)
#             results = {
#                 "predictions": predictions.tolist(),
#                 "is_malicious": (predictions == 1).tolist()
#             }
        
#         return results
        
#     except Exception as e:
#         print(f"Error during prediction: {e}")
#         return {"error": f"Prediction failed: {str(e)}"}

# def predict_and_respond(model, df):
#     """
#     Makes predictions and formats a response suitable for the packet forwarder
#     """
#     prediction_results = prediction(model, df)
    
#     # Format response for the packet forwarder
#     response = {
#         "is_malicious": any(prediction_results.get("is_malicious", [])),
#         "confidence": max(prediction_results.get("confidence", [0])) if "confidence" in prediction_results else 0,
#         "reason": "Potential malicious traffic detected by ML model"
#     }
    
#     return json.dumps(response)
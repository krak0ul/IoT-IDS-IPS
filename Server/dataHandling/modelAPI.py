import joblib
import xgboost

def import_model(model_pickle):
    return joblib.load(model_pickle)

def prediction(model, df):
    pred = model.predict(df)
    return pred
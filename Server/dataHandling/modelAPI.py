import joblib
# import xgboost
import pandas as pd

def import_model(model_pickle):
    return joblib.load(model_pickle)

def prediction(model, df):
    pred = model.predict(df)
    counts = pd.Series(pred).value_counts()
    labels = ['Non-Attack', 'Attack']  # Assuming 0 = Non-Attack, 1 = Attack

    print("val count: ")
    print(counts)
    return pred
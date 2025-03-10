import joblib
import sys

import settings

model_pickle = settings.MODEL

def import_model(model_pickle):
    return joblib.load(model_pickle)


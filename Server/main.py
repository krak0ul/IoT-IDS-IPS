import sys

from settings import PCAP_FILE, FEATURES, MODEL
from dataHandling.featureExtractPcap import pcap_to_df
from dataHandling.dataPreparation import prepareData


file_name = PCAP_FILE
features = FEATURES
model_pickle = MODEL


if __name__ == '__main__':
        df = pcap_to_df(file_name, features)
        print(df)
        df = prepareData(df)
        print(df)
        
        sys.exit(0)
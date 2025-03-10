import sys

from dataHandling.featureExtractPcap import pcap_to_df
from settings import PCAP_FILE, FEATURES, MODEL


file_name = PCAP_FILE
features = FEATURES
model_pickle = MODEL


if __name__ == '__main__':
        df = pcap_to_df(file_name, features)
        print(df)
        
        sys.exit(0)
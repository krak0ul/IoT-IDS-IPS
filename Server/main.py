import sys

from settings import PCAP_FILE, FEATURES, MODEL
from dataHandling.featureExtractPcap import extract_packets, format_raw, pcap_to_raw
from dataHandling.dataPreparation import prepareData
from dataHandling.modelAPI import import_model, prediction

file_name = PCAP_FILE
features = FEATURES
model_pickle = MODEL


if __name__ == '__main__':
        pkt_buffer = pcap_to_raw('pcaps/test.pcap')
        # print(pkt_buffer)
        packets = format_raw(pkt_buffer)

        df = extract_packets(packets, features)
        # print(df)
        df = prepareData(df)
        print(df)
        
        model = import_model(model_pickle)
        prediction = prediction(model, df)
        print("prediction: " + str(prediction))
        

        sys.exit(0)
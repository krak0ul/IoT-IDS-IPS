# IoT-IDS-IPS

## Overview

**IoT-IDS-IPS** is a cutting-edge Intrusion Detection and Prevention System (IDS/IPS) designed specifically for IoT environments. It continuously monitors network traffic, processes packets in real time, and leverages a pre-trained machine learning model to detect malicious activity. The system operates in two distinct modes:

- **IDS Mode:** Monitors and logs suspicious activity for further analysis.
- **IPS Mode:** Actively prevents malicious traffic by blocking it in real time.

This project focuses on robust security, efficient asynchronous processing, and secure client-server communication using WebSockets with token-based authentication. It also includes a command-line interface (CLI) for easy deployment, configuration, and monitoring.

---

## Architecture

The system is divided into two main components: **Client** and **Server**.

### Client Side

- **Packet Capture:**  
  Utilizes PyShark to capture live network packets from a specified interface.

- **Data Serialization & Transmission:**  
  Captured packets are serialized and transmitted to the server using TCP or WebSocket protocols.

### Server Side

- **WebSocket Server with Token Authentication:**  
  Receives packet data from clients. The first message on a new connection contains a token, which is validated to ensure that only authorized clients can send data.

- **Asynchronous Packet Processing:**  
  Uses Python's `asyncio` library to handle multiple client connections concurrently. Each incoming packet is scheduled as an asynchronous task, allowing immediate processing without waiting for the connection to close.

- **Data Extraction & Preprocessing:**  
  Processes incoming packet data through custom modules that extract relevant features, clean the data, perform label encoding, and scale numerical values using pre-fitted objects.

- **Machine Learning Prediction:**  
  A pre-trained XGBoost model classifies each packet as either benign or malicious based on the extracted features. The model was trained using the **EdgeIIoTset: Cyber Security Dataset of IoT IIoT** available on [Kaggle](https://www.kaggle.com/datasets/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot) and predicts the packet category from the following 15 options:

  - 0: Backdoor  
  - 1: DDoS_HTTP  
  - 2: DDoS_ICMP  
  - 3: DDoS_TCP  
  - 4: DDoS_UDP  
  - 5: Fingerprinting  
  - 6: MITM  
  - 7: Normal  
  - 8: Password  
  - 9: Port_Scanning  
  - 10: Ransomware  
  - 11: SQL_injection  
  - 12: Uploading  
  - 13: Vulnerability_scanner  
  - 14: XSS

- **Response Mechanism:**
  - In **IDS mode**, the system logs detailed alerts and analysis data.
  - In **IPS mode**, the system actively blocks traffic from malicious sources.

### High-Level Data Flow

```mermaid
flowchart TD
    subgraph Client
        A[Packet Capture - PyShark]
        B[Serialization & Transmission]
    end

    subgraph Server
        C[WebSocket Server - Token Auth]
        D[Asynchronous Packet Processing]
        E[Data Extraction & Preprocessing]
        F[Machine Learning Prediction - XGBoost]
        G[Detection & Response - Log/Block]
    end

    A --> B
    B --> C
    C --> D
    D --> E
    E --> F
    F --> G

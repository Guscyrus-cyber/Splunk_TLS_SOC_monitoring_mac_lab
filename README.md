**TLS SOC Monitoring Lab**

**Description**

**TLS SOC Monitoring Lab:** TLS traffic was ingested into Splunk Enterprise and analyzed to identify encrypted communications, HTTPS activity, external connections, and potential security threats through dashboards, reports, alerts, detections, visualizations, and threat-hunting investigations.

**Verify TLS Index**

TLS index already exists

**Upload TLS Dataset**


Dataset: tls_traffic.log\
Settings:

Index: tls\
Host: MacBookPro\
Sourcetype: tls_traffic

Description: TLS traffic generated from packet capture analysis was ingested into Splunk Enterprise to support encrypted traffic monitoring and HTTPS activity investigations.

Please refer to the corresponding query and supporting screenshots in the repository.

**Verify Ingestion**

Search: index=tls\
Or\
source="tls_traffic.log" host="MacBookPro" index="tls" sourcetype="tls_traffic"\
\
Purpose: Verify successful TLS data ingestion.

Please refer to the corresponding query and supporting screenshots in the repository.

**Verify Event Count**

Search:\
index=tls\
\| stats count

Purpose: Confirm TLS event availability.

Please refer to the corresponding query and supporting screenshots in the repository.

**Review TLS Traffic**

Search:\
index=tls\
\| table \_time host sourcetype \_raw

Purpose: Review encrypted traffic and HTTPS communications.

Please refer to the corresponding query and supporting screenshots in the repository.

**Identify HTTPS Traffic**

Search: index=tls 443

Purpose: Identify HTTPS communications using port 443.

Please refer to the corresponding query and supporting screenshots in the repository.

**Identify QUIC Traffic**
\
QUIC (Quick UDP Internet Connections) is a modern transport layer protocol that serves as the foundation for HTTP/3. While traditional HTTPS 443 traffic relies on TCP and TLS separately, QUIC natively integrates encryption over UDP. This allows QUIC to establish secure connections much faster and avoid the "stalling" caused by lost data packets

The fundamental differences between QUIC (UDP 443) and traditional HTTPS (TCP 443) can be broken down by their underlying technology, connection speed, reliability, and network visibility. 

Search: index=tls quic

Purpose: Identify QUIC protocol activity over UDP 443.\

Please refer to the corresponding query and supporting screenshots in the repository.

**Secure Web Applications**

index=tls (443 OR 8443)

Purpose: Identify standard and non-standard HTTPS communications.

Please refer to the corresponding query and supporting screenshots in the repository.

**Cloud and Application Traffic**

index=tls (443 OR 8443 OR 9443)

Purpose: Identify encrypted communications commonly used by cloud services and enterprise applications.

**Identify External IP Addresses**

Search:\
index=tls\
\| table \_raw\
\
Looking for entries such as:

3.221.141.237.443\
150.171.109.73.443\
17.253.3.195.443\
104.18.32.47.443\
20.189.173.23.443

Purpose: Identify external systems communicating through encrypted channels.

Please refer to the corresponding query and supporting screenshots in the repository.

**Analyst Observation**

The TLS dataset shows:

192.168.1.193 → External IP → Port 443

which indicates:

A local endpoint established encrypted communications with multiple Internet hosts using HTTPS/TLS and QUIC protocols. No clear indicators of malicious activity were observed in the captured traffic. The communications appear consistent with normal encrypted web and cloud-service activity.

### Important Finding

One IP appears repeatedly:

104.18.32.47:443

with many entries:

quic, protected

This indicates repeated encrypted HTTP/3 (QUIC) communications between the endpoint and an external service. QUIC traffic is expected for many modern websites and cloud services and demonstrates the use of encrypted UDP communications.

Threat-hunting analysis identified multiple external systems communicating with the endpoint over encrypted TLS and QUIC protocols. The investigation revealed HTTPS traffic on port 443 and repeated QUIC communications with external cloud-hosted services. No suspicious destinations were identified, demonstrating normal encrypted Internet activity and secure communications monitoring within a SOC environment.


**Search for Apple Services**

Search: index=tls 17.253

Purpose: Identify Apple-related encrypted communications.

The output indicates encrypted communications with an Apple-owned service over HTTPS/TLS.

Query used: index=tls 17.253

**Analysis**

The TLS dataset contains communications between:

192.168.1.193 and 17.253.3.195:443

using port 443 (HTTPS/TLS).

Observed activity:

192.168.1.193 → 17.253.3.195:443\
17.253.3.195:443 → 192.168.1.193

The connection shows: Flags \[P.\] which indicates data was transmitted.

and later: Flags \[F.\]which indicates the connection was gracefully closed after the data exchange completed.

**Analyst Observation**

The TLS investigation identified encrypted communications between the endpoint and an external Apple-owned service operating on port 443. The connection successfully exchanged data and terminated normally, indicating legitimate encrypted traffic rather than suspicious behavior. The activity demonstrates normal HTTPS communications with Apple infrastructure and highlights the use of TLS monitoring to identify external service providers communicating with the endpoint.

**Important Finding**

17.253.3.195:443

was observed exchanging encrypted traffic and then closing the session normally.

Indicators of a normal session:

TLS traffic over port 443\
Bidirectional communication\
Data transfer (Flags \[P.\])\
Graceful session termination (Flags \[F.\])\
No repeated failures\
No unusual ports

Analysis of TLS traffic identified encrypted HTTPS communications with Apple infrastructure on port 443. The connection successfully exchanged data and terminated normally, demonstrating legitimate encrypted communications and providing visibility into external service interactions within the TLS monitoring environment.

**Visualization**

Query:\

index=tls\
\| stats count\
\
Visualization:

Single Value

Panel Title:

TLS Event Count

Description: Displays the total number of TLS-related events ingested into the TLS index.

**Report**

Report Name: TLS Traffic Report

Description: Summarizes encrypted traffic activity observed within the TLS dataset.

**Dashboard**

Dashboard Name: TLS SOC Monitoring Dashboard

Panel Title: TLS Activity Overview

Description: Provides visibility into encrypted network communications and HTTPS activity.\

**Alert**

Query: index=tls 443

Alert Name: Encrypted Traffic Detection

Description: Detects encrypted network communications using TLS and HTTPS protocols.

**Detection Rule**

Query:\
index=tls\
\| search quic OR 443

Detection Name: TLS Communication Detection

Description: Detects encrypted communications and secure network protocols observed in the environment.

**Threat Hunting**
Query:\
index=tls\
\| table \_time host sourcetype \_raw

Purpose: Investigate encrypted communications, external destinations, cloud services, and unusual TLS activity that may indicate malware communications, command-and-control traffic, or unauthorized external connections.


In Threat Hunting, the TLS investigation revealed several useful findings.

**Threat Hunting Findings**

#### **1. Multiple External Encrypted Connections**

The endpoint communicated with several external IP addresses over port 443:

3.221.141.237\
150.171.109.73\
17.253.3.195\
104.18.32.47\
20.189.173.23\
40.112.143.140

This indicates encrypted HTTPS/TLS communications with multiple Internet services.

#### **2. Apple Service Communications**

Encrypted traffic was observed between:

192.168.1.193 ↔ 17.253.3.195:443

The connection exchanged data and terminated normally, indicating legitimate Apple-related TLS communications.

#### **3. QUIC / HTTP3 Activity**

The most frequent activity involved:

104.18.32.47:443

with repeated entries:

quic, protected

This indicates encrypted HTTP/3 (QUIC) communications over UDP 443. Modern browsers and cloud services commonly use QUIC for performance improvements.

#### **4. Encrypted Data Transfers**

Several connections contained:

Flags \[P.\]

which indicates application data was transmitted through the encrypted session.

#### **5. Connection Termination Events**

The dataset contains:

Flags \[F.\]

indicating graceful session closure.

and

Flags \[R.\]

indicating connection resets. These can occur during normal network activity, application shutdowns, or interrupted sessions.

### Assessment

Threat hunting identified normal encrypted Internet communications using TLS and QUIC protocols. The investigation revealed connections to multiple external services, encrypted data transfers, Apple-related HTTPS traffic, and repeated HTTP/3 communications. No obvious indicators of compromise, suspicious destinations, malware communications, or command-and-control activity were observed in the dataset. The activity appears consistent with legitimate encrypted web and cloud-service usage.

TLS threat-hunting analysis identified encrypted HTTPS and QUIC communications with multiple external services. The investigation revealed normal encrypted web traffic, Apple service communications, HTTP/3 activity, and secure data transfers, demonstrating how TLS monitoring can provide visibility into encrypted network activity within a SOC environment.



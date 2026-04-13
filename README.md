# ServerLogSOC
**ServerLogSOC** is a security log analysis dashboard that enables analysts to upload access logs, detect suspicious activity, and understand incidents through summaries, timelines, and SOC-style insights.

## Table contents

- [ Project Structure](#-project-structure)
- [ Anomaly Detection Approach](#-anomaly-detection-approach)
- [ Confidence Score](#-confidence-score)
- [ Quick Start](#-quick-start)
- [Run with Docker](#-run-with-docker)
- [ Run Without Docker](#️-run-without-docker)
- [ Usage](#-usage)
- [ Core Functionality ](#core-functionality)
- [ Common Issue (macOS Port 5000 Conflict)](#️-common-issue-macos-port-5000-conflict)

## 📁 Project Structure

```
Frontend/
├── Dockerfile
├── clerk-react/           # Clerk authentication setup
├── src/
│   ├── pages/
│   │   ├── Dashboard.tsx
│   │   ├── Dashboard.css
│   │   ├── Analytics.tsx
│   │   └── Analytics.css
│   ├── App.tsx
│   └── App.css
└── package.json
Backend/
├── Dockerfile
├── uploaded_logs/        # Temporary log storage
├── parser.py             # Raw → structured logs
├── analytics.py          # Insight generation
├── app.py                # Flask API
└── requirements.txt
logs_samples/            # Logs are from: http://www.secrepo.com/self.logs/ ( ‼️ ⚠️ if not using provided sample logs then after downloading it, extract and rename it to .log to .txt.)

docker-compose.yml        # Runs frontend + backend
```


## Anomaly Detection Approach

The system looks for suspicious activity using 5 simple checks:

- **Directory Scanning** — an IP trying many different URLs and getting lots of 404 errors  
- **Rate Abuse** — an IP hitting rate limits (429 errors) again and again  
- **Burst Activity** — an IP making too many requests in a short time (60 seconds)  
- **Sensitive File Access** — attempts to access important paths like `/admin` or `/etc/passwd`  
- **Data Exfiltration** — large downloads from unusual or risky paths  


### Confidence Score

Each suspicious IP gets a score based on how risky it looks.

The score increases based on:
- How many different checks it triggered. 
- How many suspicious requests it made. 
- How quickly the activity happened.  

### Example

- One type of suspicious activity → score around **0.28**  
- Three different types within 5 minutes → score around **0.95**  

Higher score = more likely the IP is malicious.

## Quick Start

* **Live Link**: https://serverlogsoc.web.app/  (Deployed on GCP)
( ‼️ ⚠️ if not using provided sample logs then after downloading it, extract and rename it to .log to .txt.)



## Run with Docker

1. Clone the repo:
```bash
   git clone https://github.com/ReethikaGogireddy/ServerLogSOC.git
   cd ServerLogSOC
```

2. Set up backend keys:
```bash
   # create backend/.env
   echo "VIRUSTOTAL_API_KEY=your_key_here" > backend/.env
```

3. Set up frontend keys:
```bash
   # create frontend/.env
   echo "VITE_CLERK_PUBLISHABLE_KEY=your_key_here" > frontend/.env
   echo "VITE_API_URL=http://localhost:5000" >> frontend/.env
```

4. Run:
```bash
   docker compose up --build
```

5. Open [http://localhost:5173](http://localhost:5173)


## Run Without Docker

### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# create backend/.env
echo "VIRUSTOTAL_API_KEY=your_key_here" > .env

python app.py
```

### Frontend
```bash
cd frontend
npm install

# create frontend/.env
echo "VITE_CLERK_PUBLISHABLE_KEY=your_key_here" > .env
echo "VITE_API_URL=http://localhost:5000" >> .env

npm run dev
```

Open [http://localhost:5173](http://localhost:5173)


> Get your keys:
> - **Clerk**: https://clerk.com → Create app → API Keys → Publishable Key
> - **VirusTotal**: https://virustotal.com → Sign up → Profile → API Key
> - VirusTotal is optional — all features work without it except referrer threat analysis


### Access

These cannnot be accessed without login
* Frontend: [http://localhost:5173](http://localhost:5173) 
* Backend: [http://localhost:5000](http://localhost:5000)

##  Core Functionality

### Log Parsing
Transforms raw server logs into structured, analyzable data.

- **`parse_log_line`** – Converts each raw log entry into structured fields (IP, path, status, etc.)
- **`parse_request`** – Extracts HTTP method, endpoint, and protocol.
- **`parse_timestamp`** – Normalizes timestamps into ISO format.
- **`parse_log_file`** – Processes entire log files line-by-line.
- **`parse_uploaded_logs`** – Aggregates and parses all uploaded logs.


###  Traffic Analytics
Generates insights into usage patterns and system behavior.

- **`get_most_accessed_pages` / `get_least_accessed_pages`** – Identify popular and underused endpoints.  
- **`get_top_ips` / `get_most_active_ip`** – Highlight high-traffic sources.  
- **`get_status_breakdown`** – Categorizes responses (allowed, blocked, errors).  
- **`get_device_breakdown`** – Classifies traffic (bot, mobile, desktop).  
- **`get_top_referrers`** – Tracks incoming traffic sources.  
- **`get_timeline`** – Visualizes request volume over time.


### Threat Detection Engine
Detects suspicious activity using rule-based heuristics.

- **`detect_404_scanning`** – Identifies directory scanning attempts. 
- **`detect_429_abuse`** – Flags rate-limit abuse and brute-force behavior.  
- **`detect_burst_activity`** – Detects sudden spikes in request volume.  
- **`detect_sensitive_access`** – Flags access to sensitive endpoints.  
- **`detect_data_exfiltration`** – Detects large suspicious data transfers.  


### Risk Scoring & Intelligence
Prioritizes threats based on severity and behavior patterns.

- **`compute_ip_confidence`** – Assigns a risk score to each IP.  
- **`build_event_feed`** – Aggregates all detected threats into a unified alert stream.  which is later on displays in the form of alerts.
- **`classify_attack`** – Groups alerts into attack categories.   
- **`get_attack_distribution`** – Summarizes attack patterns for visualization.  
- **`enrich_referrers_with_virustotal`** – Adds external threat intelligence. 



### End-to-End Analysis
- **`analyze_logs`** – Runs full pipeline (parsing → analytics → detection → scoring) and returns dashboard-ready insights . 



### API Endpoints
- **`/upload`** – Upload and store log files  
- **`/parse`** – Retrieve structured log data  
- **`/analyze`** – Get full analytics and threat insights  
- **`/health`** – Check backend status  


## Usage

1. Sign up / log in  By Opening: [http://localhost:5173](http://localhost:5173)
2. Upload log files via the **Upload**
3. Navigate to **Analytics** to view:

   * Parsed logs
   * Suspicious activity
   * Visual insights


## Common Issue (macOS Port 5000 Conflict)

If port **5000** is in use:

* Go to: **System Settings → General → AirDrop & Handoff**
* Turn **AirPlay Receiver OFF**





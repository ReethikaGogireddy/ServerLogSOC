# ServerLogSOC
**ServerLogSOC** is a security log analysis dashboard that enables analysts to upload access logs, detect suspicious activity, and understand incidents through summaries, timelines, and SOC-style insights.


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

docker-compose.yml        # Runs frontend + backend
```
## 🧠 Anomaly Detection Approach

The system looks for suspicious activity using 5 simple checks:

- **Directory Scanning** — an IP trying many different URLs and getting lots of 404 errors  
- **Rate Abuse** — an IP hitting rate limits (429 errors) again and again  
- **Burst Activity** — an IP making too many requests in a short time (60 seconds)  
- **Sensitive File Access** — attempts to access important paths like `/admin` or `/etc/passwd`  
- **Data Exfiltration** — large downloads from unusual or risky paths  

---

### 🔢 Confidence Score

Each suspicious IP gets a score based on how risky it looks.

The score increases based on:
- How many different checks it triggered  
- How many suspicious requests it made  
- How quickly the activity happened  

---

### 📊 Example

- One type of suspicious activity → score around **0.28**  
- Three different types within 5 minutes → score around **0.95**  

Higher score = more likely the IP is malicious.

## 🚀 Quick Start ( No Setup Required, Only log files are needed to upload)

* **Live Link**: https://serverlogsoc.web.app/ 

## 🔗 Repository

GitHub:
[https://github.com/ReethikaGogireddy/ServerLogSOC](https://github.com/ReethikaGogireddy/ServerLogSOC)



## 🚀 Docker Setup 

### Prerequisites

* Install **Docker Desktop**

### Run the App

```bash
docker compose up --build
```

### Access

* Frontend: [http://localhost:5173](http://localhost:5173)
* Backend: [http://localhost:5000](http://localhost:5000)


## 🧑‍💻 Usage

1. Sign up / log in
2. Upload log files via the **Dashboard**
3. Navigate to **Analytics** to view:

   * Parsed logs
   * Suspicious activity
   * Visual insights


## ⚠️ Common Issue (macOS Port 5000 Conflict)

If port **5000** is in use:

* Go to: **System Settings → General → AirDrop & Handoff**
* Turn **AirPlay Receiver OFF**


## 🛠️ Manual Setup (Without Docker)

### Backend (Flask)

```bash
cd Backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create `.env`:

```
API_KEY=your_api_key
CLERK_SECRET_KEY=your_secret_key
```

Run:

```bash
python app.py
```

### Frontend (React)

```bash
cd Frontend
npm install
```

Create `.env`:

```
VITE_CLERK_PUBLISHABLE_KEY=your_key
```

Run:

```bash
npm run dev
```

## ✅ You're Ready

* Open: [http://localhost:5173](http://localhost:5173)
* Upload logs
* Analyze results in the dashboard


## 🔗 Repository

GitHub:
[https://github.com/ReethikaGogireddy/ServerLogSOC](https://github.com/ReethikaGogireddy/ServerLogSOC)




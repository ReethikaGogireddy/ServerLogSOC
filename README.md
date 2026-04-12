# ServerLogSOC
**ServerLogSOC** is a security log analysis dashboard that enables analysts to upload access logs, detect suspicious activity, and understand incidents through summaries, timelines, and SOC-style insights.


## 📦 Tech Stack

* **Frontend:** React (Vite), Clerk (Auth)
* **Backend:** Flask (Python)
* **Visualization:** Chart components (Bar, Pie)
* **Containerization:** Docker, Docker Compose

## 📁 Project Structure

```
Frontend/
├── Dockerfile
├── clerk-react/           # Clerk authentication setup
├── src/
│   ├── components/
│   │   ├── BarGraph.tsx
│   │   ├── PieChart.tsx
│   │   └── NavBar.tsx
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

## 🚀 Quick Start ( No Setup Required, Only log files are needed to upload)

* **Host URL**: https://serverlogsoc.web.app/ 

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




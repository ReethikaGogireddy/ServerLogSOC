# ServerLogSOC
ServerLogSOC is a security log analysis dashboard that lets analysts upload access logs, parse them, detect suspicious behavior, and quickly understand what happened through summaries, timelines, and SOC-style event messages.


# File Structure

Frontend/
│── Dockerfile                # Configuration to build the frontend container
│── clerk-react/              # Setup for Clerk authentication integration
│── src/
│   ├── components/
│   │   ├── BarGraph.tsx      # Bar chart visualization component
│   │   ├── NavBar.tsx        # Navigation bar component
│   │   ├── PieChart.tsx      # Pie chart visualization component
│   │
│   ├── pages/
│   │   ├── Analytics.tsx     # Displays analyzed log data
│   │   ├── Analytics.css     # Styles for Analytics page
│   │   ├── Dashboard.tsx     # Main page after login; allows log upload
│   │   ├── Dashboard.css     # Styles for Dashboard page
│   │
│   ├── App.tsx               # Root React component
│   ├── App.css               # Global styles for the app
│
│── package.json              # Frontend dependencies and scripts

Backend/
│── Dockerfile                # Configuration to build the backend container
│── uploaded_logs/            # Temporary storage for uploaded log files (inside container)
│── analytics.py              # Processes parsed logs and generates insights
│── parser.py                 # Converts raw logs into structured JSON data
│── app.py                    # Flask application with routes and API endpoints
│── requirements.txt          # Python dependenciese

docker-compose.yml            # Orchestrates frontend and backend services,
                              # builds containers, and enables communication between them

## 🚀 How to Run the Project

### 1. Clone or Download the Repository

* Go to: [https://github.com/ReethikaGogireddy/ServerLogSOC](https://github.com/ReethikaGogireddy/ServerLogSOC)
* Click **Code** → choose one of the following:

  * **Download ZIP**, then extract it
  * OR copy the repo URL:

    ```
    https://github.com/ReethikaGogireddy/ServerLogSOC.git
    ```
* Open **VS Code**

  * Click **“Clone Git Repository”**
  * Paste the `.git` URL and choose a folder

---

### 2. Run Using Docker (Recommended)

#### Prerequisites:

* Install and open **Docker Desktop**

#### Steps:

* Open the project folder in VS Code
* Open a terminal in the root directory
* Run:

  ```
  docker compose up --build
  ```

This will:

* Build both frontend and backend
* Install dependencies
* Start the application

---

### 3. Access the Application

* Open your browser and go to:

  ```
  http://localhost:5173/
  ```

---

### 4. First-Time Usage

* Create an account (authentication is enabled)
* After logging in:

  * You’ll land on the **Dashboard**
  * Upload your log files
  * Click **“Analytics”** (top-right) to view insights

---

### ⚠️ Common Issue (Port 5000 Conflict – macOS)

If you see an error about port **5000 already in use**:

* This is often caused by **AirPlay Receiver**
* Fix:
  * Go to **System Settings → General → AirDrop & Handoff**
  * Turn **AirPlay Receiver OFF**


## 🛠️ Run Without Docker (Manual Setup)

If you prefer not to use Docker, you can run the frontend and backend separately.

### 📌 Prerequisites

Make sure you have installed:

* **Node.js** (v16+ recommended)
* **npm** (comes with Node)
* **Python** (v3.8+ recommended)
* **pip**
---

## 🔧 Backend Setup (Flask)

1. Navigate to the backend folder:
   ```
   cd Backend
   ```
2. Create a virtual environment:
   ```
   python -m venv venv
   ```
3. Activate the virtual environment:
   * On macOS/Linux:
     ```
     source venv/bin/activate
     ```
   * On Windows:
     ```
     venv\Scripts\activate
     ```
4. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
5. Set up environment variables (create a `.env` file):
   ```
   API_KEY=your_api_key_here
   CLERK_SECRET_KEY=your_secret_key
   ```
6. Run the Flask server:
   ```
   python app.py
   ```
👉 Backend will run on: http://localhost:5000
---

## 🎨 Frontend Setup (React + Vite)

1. Open a new terminal and navigate to the frontend folder:
   ```
   cd Frontend
   ```
2. Install dependencies:
   ```
   npm install
   ```
3. Create a `.env` file:
   ```
   VITE_CLERK_PUBLISHABLE_KEY=your_publishable_key
   ```
4. Start the development server:
   ```
   npm run dev
   ```
👉 Frontend will run on:
```
http://localhost:5173
```

## ✅ You're Ready!

* Open: [http://localhost:5173](http://localhost:5173)
* Create an account
* Upload log files via the Dashboard (The fisrt page you will see after log in)
* View results in the **Analytics** page
---



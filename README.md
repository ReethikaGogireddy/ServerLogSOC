# ServerLogSOC
ServerLogSOC is a security log analysis dashboard that lets analysts upload access logs, parse them, detect suspicious behavior, and quickly understand what happened through summaries, timelines, and SOC-style event messages.


# File Structure

Frontend/
    Dockerfile - The setup code for frontend
    clerk-react - This is created because it necessari to use clerk-library for authentication.
    src/
        components/
            BarGraph.tsx
            NavBar.tsx
            PieChart.tsx
        pages/
            Analytics.tsx - The page that displays the analytics of logs.
            Analytics.css - This is css file for Analytics.tsx.
            Dashboard.tsx - The first page that user sees after log in, where the user 
                            can upload log pages.     
            Dashboard.css - This is css file for Dashboard.tsx.
        App.css - This is css file for App.tsx. (Main Page)
        App.tsx - The main file.

Backend/
    Dockerfile - The setup code for backend
    uploaded_logs/ - The uploaded logs are stored temporarily in the container filesystem.
    analytics.py - The logics for analyzing logs, by taking the JSON objects from parser.py.
    app.py - The main file for Flask, which as routes and end points.
    parser.py - This takes logs from the uploaded_logs folder and creates JSON Objects out of those.
    requirements.txt - This file consists the required libraries to run the backend. (for frontend  you can install required libraries using "npm i" which basically installs required libraries using package.json)

docker-compose.yml - To run the application. It defines and runs both frontend and backend services, builds them using their respective Dockerfiles, and allows them to communicate





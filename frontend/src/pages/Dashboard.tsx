import { NavLink } from "react-router-dom";
import { UserButton } from "@clerk/clerk-react";
import "./Dashboard.css";

function Dashboard() {
  return (
    <div className="dashboard-container">
      <nav className="navbar">
        <div className="nav-left">
          <h1>ServerLogSOC</h1>
          <p>SOC log analysis dashboard</p>
        </div>
        <div className="nav-right">
          <NavLink to="/dashboard" className={({ isActive }) =>
            isActive ? "nav-link active" : "nav-link"}>Dashboard</NavLink>
          <NavLink to="/analytics" className={({ isActive }) =>
            isActive ? "nav-link active" : "nav-link"}>Analytics</NavLink>
          <UserButton />
        </div>
      </nav>

      <main className="main-content">
        <h2>Upload Logs</h2>
        <p>Upload server logs to begin analysis and threat detection.</p>
        <div className="upload-box">
          <p>Drag & drop log files here, or click to browse</p>
          <button className="upload-btn">Browse Files</button>
        </div>
      </main>
    </div>
  );
}

export default Dashboard;
import { NavLink } from "react-router-dom";
import { UserButton } from "@clerk/clerk-react";
import "./Dashboard.css";
import { useState } from "react";

function Dashboard() {
  const [file, setFile] = useState<File | null>(null);
  const [message, setMessage] = useState("");

  const API = import.meta.env.VITE_API_URL;
  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!file) {
      setMessage("Please choose a log file first.");
      return;
    }

    const allowed = [".log", ".txt"];
    if (!allowed.some((ext) => file.name.endsWith(ext))) {
      setMessage("Only .log or .txt files allowed");
      return;
    }

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${API}/upload`, {
        method: "POST",
        body: formData,
      });

      const data = await response.json();

      if (response.ok) {
        setMessage(data.message || "File uploaded successfully.");
        setFile(null);
      } else {
        setMessage(
          data.message || `Upload failed with status ${response.status}.`,
        );
      }
    } catch (error) {
      console.error("Upload error:", error);
      setMessage(
        "Could not connect to backend. Make sure Flask is running on http://127.0.0.1:5000",
      );
    }
  };

  return (
    <div className="dashboard-container">
      <nav className="navbar">
        <div className="nav-left">
          <h1>ServerLogSOC</h1>
          <p>SOC log analysis dashboard</p>
        </div>
        <div className="nav-right">
          <NavLink
            to="/dashboard"
            className={({ isActive }) =>
              isActive ? "nav-link active" : "nav-link"
            }
          >
          Upload
          </NavLink>
          <NavLink
            to="/analytics"
            className={({ isActive }) =>
              isActive ? "nav-link active" : "nav-link"
            }
          >
            Analytics
          </NavLink>
          <UserButton />
        </div>
      </nav>

      <main className="main-content">
        <h2>Upload Logs</h2>
        <p>Upload server logs to begin analysis and threat detection.</p>
        <form onSubmit={handleUpload} className="upload-box">
          <p>Drag & drop log files here, or click to browse</p>
          <input
            type="file"
            accept=".log,.txt"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            style={{ display: "none" }}
            id="fileInput"
          />
          <label htmlFor="fileInput" className="upload-btn">
            Browse Files
          </label>
          &nbsp; &nbsp;
          {file && <p>{file.name}</p>}
          <button type="submit" className="upload-btn">
            Upload
          </button>
          {message && <p className="upload-message">{message}</p>}
        </form>
      </main>
    </div>
  );
}

export default Dashboard;

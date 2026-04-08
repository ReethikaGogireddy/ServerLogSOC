import { SignedIn, SignIn } from "@clerk/clerk-react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import "./App.css";

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          // The user will be redirected to the dashboard after signing in, or if they are already signed in
          <Route
            path="/"
            element={
             <div className="signin-page">
                <h1>Server Log SOC</h1>
                <p>
                  Welcome to the Server Log Security Operations Center (SOC)
                  dashboard. Here you can monitor and analyze server logs for
                  potential security threats and incidents.
                </p>

                <SignIn fallbackRedirectUrl="/dashboard" />
              </div>
            }
          />

         // The dashboard route is protected and only accessible to signed-in users
          <Route
            path="/dashboard"
            element={
              <SignedIn>
                <Dashboard />
              </SignedIn>
            }
          />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;

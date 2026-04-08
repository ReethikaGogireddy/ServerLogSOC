
import { SignIn,SignedOut,SignedIn, UserButton } from '@clerk/clerk-react'
import './App.css'

function App() {
  

  return (
    <>
      <div className="App">

      <h1>Server Log SOC</h1>
        <p>Welcome to the Server Log Security Operations Center (SOC) dashboard. Here you can monitor and analyze server logs for potential security threats and incidents.</p>
        

      <SignedOut>
        <SignIn fallbackRedirectUrl="/dashboard" />
      </SignedOut>

      
        
        <SignedIn>
        <div className="app-container">
          <h1>Server Log SOC</h1>
          <UserButton />
          <h2>Upload Page</h2>
        </div>
      </SignedIn>
      </div>
      
    </>
  )
}

export default App

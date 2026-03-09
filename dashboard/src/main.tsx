import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { PSProvider } from './lib/powersync/PowerSyncProvider'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <PSProvider>
      <App />
    </PSProvider>
  </StrictMode>,
)

import React from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Sidebar from './components/Sidebar.tsx'
import Header from './components/Header.tsx'
import Dashboard from './pages/Dashboard.tsx'
import Findings from './pages/Findings.tsx'
import Settings from './pages/Settings.tsx'

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen bg-grid overflow-hidden" style={{ background: '#010812' }}>
        <Sidebar />
        <div className="flex-1 flex flex-col overflow-hidden">
          <Header />
          <main className="flex-1 overflow-y-auto p-6">
            <Routes>
              <Route path="/"          element={<Dashboard />} />
              <Route path="/findings"  element={<Findings />} />
              <Route path="/settings"  element={<Settings />} />
              <Route path="*"          element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
    </BrowserRouter>
  )
}

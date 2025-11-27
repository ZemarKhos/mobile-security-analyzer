import { Routes, Route } from 'react-router-dom'
import { AuthProvider } from './contexts/AuthContext'
import Layout from './components/Layout'
import HomePage from './pages/HomePage'
import ReportsPage from './pages/ReportsPage'
import ComprehensiveReportPage from './pages/ComprehensiveReportPage'
import AISettingsPage from './pages/AISettingsPage'
import RulesPage from './pages/RulesPage'
import LoginPage from './pages/LoginPage'
import ComparePage from './pages/ComparePage'
import DASTPage from './pages/DASTPage'

function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<Layout />}>
          <Route index element={<HomePage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="reports/:id" element={<ComprehensiveReportPage />} />
          <Route path="reports/:id/compare" element={<ComparePage />} />
          <Route path="dast" element={<DASTPage />} />
          <Route path="settings/ai" element={<AISettingsPage />} />
          <Route path="settings/rules" element={<RulesPage />} />
        </Route>
      </Routes>
    </AuthProvider>
  )
}

export default App

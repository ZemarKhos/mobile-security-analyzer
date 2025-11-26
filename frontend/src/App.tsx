import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import HomePage from './pages/HomePage'
import ReportsPage from './pages/ReportsPage'
import ComprehensiveReportPage from './pages/ComprehensiveReportPage'
import AISettingsPage from './pages/AISettingsPage'
import RulesPage from './pages/RulesPage'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<HomePage />} />
        <Route path="reports" element={<ReportsPage />} />
        <Route path="reports/:id" element={<ComprehensiveReportPage />} />
        <Route path="settings/ai" element={<AISettingsPage />} />
        <Route path="settings/rules" element={<RulesPage />} />
      </Route>
    </Routes>
  )
}

export default App

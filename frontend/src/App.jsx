import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
} from 'react-router-dom'

import ProtectedRoute from './components/ProtectedRoute.jsx'
import PublicOnlyRoute from './components/PublicOnlyRoute.jsx'
import AuthProvider from './context/AuthProvider.jsx'
import DashboardPage from './pages/DashboardPage.jsx'
import BenchmarksPage from './pages/BenchmarksPage.jsx'
import LoginPage from './pages/LoginPage.jsx'
import MyFilesPage from './pages/MyFilesPage.jsx'
import RegisterPage from './pages/RegisterPage.jsx'
import SharedFilesPage from './pages/SharedFilesPage.jsx'
import SharePage from './pages/SharePage.jsx'
import UploadPage from './pages/UploadPage.jsx'
import SecurityPage from './pages/SecurityPage.jsx'
import AdaptiveEvaluationPage from './pages/AdaptiveEvaluationPage.jsx'

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route element={<PublicOnlyRoute />}>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
          </Route>

          <Route element={<ProtectedRoute />}>
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/upload" element={<UploadPage />} />
            <Route path="/files" element={<MyFilesPage />} />
            <Route path="/my-files" element={<MyFilesPage />} />
            <Route path="/files/:fileId/share" element={<SharePage />} />
            <Route path="/shared-with-me" element={<SharedFilesPage mode="received" />} />
            <Route path="/shared-by-me" element={<SharedFilesPage mode="sent" />} />
            <Route path="/benchmarks" element={<BenchmarksPage />} />
            <Route path="/security" element={<SecurityPage />} />
            <Route path="/adaptive-evaluation" element={<AdaptiveEvaluationPage />} />
          </Route>

          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}


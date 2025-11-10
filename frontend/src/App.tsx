import { Routes, Route } from 'react-router-dom';
import LoginPage from './pages/Login.tsx';
import AlquimistaPage from './pages/Alquimista.tsx';
import SupervisorPage from './pages/Supervisor.tsx';
import ProtectedRoute from './components/ProtectedRoute.tsx';

const App = () => {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={(
          <ProtectedRoute>
            <AlquimistaPage />
          </ProtectedRoute>
        )}
      />
      <Route
        path="/supervisor"
        element={(
          <ProtectedRoute>
            <SupervisorPage />
          </ProtectedRoute>
        )}
      />
    </Routes>
  );
};

export default App;

import { Routes, Route } from 'react-router-dom';
import LoginPage from './pages/Login.tsx';
import AlquimistaPage from './pages/Alquimista.tsx';
import SupervisorPage from './pages/Supervisor.tsx';

const App = () => {
  return (
    <Routes>
      <Route path="/" element={<AlquimistaPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/supervisor" element={<SupervisorPage />} />
    </Routes>
  );
};

export default App;

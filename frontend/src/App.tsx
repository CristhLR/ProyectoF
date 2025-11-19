import { Routes, Route, Navigate } from "react-router-dom";
import LoginPage from "./pages/Login.tsx";
import RegisterPage from "./pages/Register.tsx";
import AlquimistaPage from "./pages/Alquimista.tsx";
import SupervisorPage from "./pages/Supervisor.tsx";
import ProtectedRoute from "./components/ProtectedRoute.tsx";
import TopBar from "./components/TopBar.tsx";

const App = () => {
  const isAuthenticated =
    typeof window !== "undefined" && !!localStorage.getItem("token");
  const role =
    typeof window !== "undefined" ? localStorage.getItem("role") : null;

  return (
    <>
      <TopBar />
      <Routes>
        {/* login siempre disponible */}
        <Route path="/login" element={<LoginPage />} />

        {/* register solo si NO hay sesión */}
        <Route
          path="/register"
          element={
            isAuthenticated ? <Navigate to="/" replace /> : <RegisterPage />
          }
        />

        {/* panel alquimista por defecto */}
        <Route
          path="/"
          element={
            <ProtectedRoute>
              {role === "supervisor" ? (
                <Navigate to="/supervisor" replace />
              ) : (
                <AlquimistaPage />
              )}
            </ProtectedRoute>
          }
        />

        {/* panel supervisor */}
        <Route
          path="/supervisor"
          element={
            <ProtectedRoute>
              <SupervisorPage />
            </ProtectedRoute>
          }
        />

        {/* cualquier otra cosa → login */}
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </>
  );
};

export default App;

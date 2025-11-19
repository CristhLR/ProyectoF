import { FormEvent, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { apiFetch } from "../api/client";
import type { AuthResponse } from "./Login";
import { persistAuthSession } from "./Login";

const ROLES_VALIDOS: Array<AuthResponse["user"]["rango"]> = [
  "alquimista",
  "supervisor",
];

const Register = () => {
  const navigate = useNavigate();

  const [nombre, setNombre] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [especialidad, setEspecialidad] = useState("");
  const [rango, setRango] =
    useState<AuthResponse["user"]["rango"]>("alquimista");

  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    const token = localStorage.getItem("token");
    const role = localStorage.getItem("role");
    if (token && role) {
      navigate(role === "supervisor" ? "/supervisor" : "/", { replace: true });
    }
  }, [navigate]);

  const canSubmit = useMemo(() => {
    return (
      nombre.trim() !== "" &&
      email.trim() !== "" &&
      password.trim() !== "" &&
      ROLES_VALIDOS.includes(rango)
    );
  }, [nombre, email, password, rango]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!canSubmit) return;

    setError(null);
    setLoading(true);

    try {
      // 1) registrar en el backend
      await apiFetch("/auth/register", {
        method: "POST",
        body: JSON.stringify({
          nombre,
          email,
          password,
          especialidad: especialidad || undefined,
          rango,
        }),
      });

      const loginData = await apiFetch<AuthResponse>("/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email,
          password,
        }),
      });

      persistAuthSession(loginData);

      navigate(loginData.user.rango === "supervisor" ? "/supervisor" : "/", {
        replace: true,
      });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main style={{ maxWidth: 480, margin: "0 auto", padding: "1.5rem" }}>
      <h1>Crear cuenta</h1>
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: "0.75rem" }}>
          <label htmlFor="nombre">Nombre</label>
          <input
            id="nombre"
            type="text"
            value={nombre}
            onChange={(event) => setNombre(event.target.value)}
            required
          />
        </div>

        <div style={{ marginBottom: "0.75rem" }}>
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
          />
        </div>

        <div style={{ marginBottom: "0.75rem" }}>
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
          />
        </div>

        <div style={{ marginBottom: "0.75rem" }}>
          <label htmlFor="especialidad">Especialidad (opcional)</label>
          <input
            id="especialidad"
            type="text"
            value={especialidad}
            onChange={(event) => setEspecialidad(event.target.value)}
            placeholder="Ej. Transmutación avanzada"
          />
        </div>

        <div style={{ marginBottom: "0.75rem" }}>
          <label htmlFor="rango">Rango</label>
          <select
            id="rango"
            value={rango}
            onChange={(event) =>
              setRango(event.target.value as AuthResponse["user"]["rango"])
            }
            required
          >
            {ROLES_VALIDOS.map((rol) => (
              <option key={rol} value={rol}>
                {rol.charAt(0).toUpperCase() + rol.slice(1)}
              </option>
            ))}
          </select>
        </div>

        <button type="submit" disabled={loading || !canSubmit}>
          {loading ? "Creando cuenta..." : "Registrarse"}
        </button>
      </form>

      {error && (
        <p role="alert" style={{ color: "red", marginTop: "1rem" }}>
          {error}
        </p>
      )}

      <p style={{ marginTop: "1rem" }}>
        ¿Ya tienes cuenta? <Link to="/login">Inicia sesión</Link>
      </p>
    </main>
  );
};

export default Register;

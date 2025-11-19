import { Link, useLocation, useNavigate } from "react-router-dom";

const TopBar = () => {
  const location = useLocation();
  const navigate = useNavigate();

  const isLogged =
    typeof window !== "undefined" && !!localStorage.getItem("token");
  const role =
    typeof window !== "undefined" ? localStorage.getItem("role") : null;

  const handleLogout = () => {
    if (typeof window !== "undefined") {
      localStorage.removeItem("token");
      localStorage.removeItem("role");
      localStorage.removeItem("user");
    }
    navigate("/login", { replace: true });
  };

  return (
    <header className="w-full bg-slate-900 text-white mb-6">
      <div className="max-w-6xl mx-auto flex items-center justify-between px-4 py-3 gap-4">
        <div
          className="font-bold text-lg cursor-pointer"
          onClick={() => navigate(isLogged ? "/" : "/login")}
        >
          Alquimia Central
        </div>

        <nav className="flex gap-3 items-center text-sm">
          {/* cuando no estoy logueado */}
          {!isLogged && (
            <>
              <Link
                to="/login"
                className={
                  location.pathname === "/login"
                    ? "underline font-semibold"
                    : "opacity-90 hover:opacity-100"
                }
              >
                Login
              </Link>
              <Link
                to="/register"
                className={
                  location.pathname === "/register"
                    ? "underline font-semibold"
                    : "opacity-90 hover:opacity-100"
                }
              >
                Registro
              </Link>
            </>
          )}

          {/* cuando estoy logueado como alquimista */}
          {isLogged && role !== "supervisor" && (
            <Link
              to="/"
              className={
                location.pathname === "/"
                  ? "underline font-semibold"
                  : "opacity-90 hover:opacity-100"
              }
            >
              Panel
            </Link>
          )}

          {/* cuando estoy logueado como supervisor */}
          {isLogged && role === "supervisor" && (
            <Link
              to="/supervisor"
              className={
                location.pathname === "/supervisor"
                  ? "underline font-semibold"
                  : "opacity-90 hover:opacity-100"
              }
            >
              Panel supervisor
            </Link>
          )}

          {isLogged && (
            <button
              type="button"
              onClick={handleLogout}
              className="bg-slate-700 hover:bg-slate-600 px-3 py-1 rounded"
            >
              Salir
            </button>
          )}
        </nav>
      </div>
    </header>
  );
};

export default TopBar;

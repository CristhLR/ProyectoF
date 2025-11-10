import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiFetch } from '../api/client.ts';

type Transmutacion = {
  id: number;
  alquimista_id: number;
  material_id: number;
  estado: string;
  costo: number;
  resultado?: string;
};

type Auditoria = {
  id: number;
  tipo: string;
  detalle: string;
  created_at: string;
};

const Supervisor = () => {
  const navigate = useNavigate();
  const [transmutaciones, setTransmutaciones] = useState<Transmutacion[]>([]);
  const [auditorias, setAuditorias] = useState<Auditoria[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login', { replace: true });
      return;
    }

    const role = localStorage.getItem('role');
    if (role && role !== 'supervisor') {
      navigate('/', { replace: true });
      return;
    }

    let active = true;

    const loadData = async () => {
      try {
        const [transmutacionesData, auditoriasData] = await Promise.all([
          apiFetch<Transmutacion[]>('/transmutaciones'),
          apiFetch<Auditoria[]>('/auditorias'),
        ]);

        if (!active) {
          return;
        }

        setTransmutaciones(transmutacionesData);
        setAuditorias(auditoriasData);
      } catch (err) {
        if (active) {
          setError((err as Error).message);
        }
      }
    };

    loadData();

    return () => {
      active = false;
    };
  }, [navigate]);

  return (
    <main>
      <h1>Panel de Supervisor</h1>

      {error && <p role="alert">{error}</p>}

      <section>
        <h2>Transmutaciones</h2>
        {transmutaciones.length === 0 ? (
          <p>No hay transmutaciones registradas.</p>
        ) : (
          <ul>
            {transmutaciones.map((transmutacion) => (
              <li key={transmutacion.id}>
                #{transmutacion.id} - Alquimista {transmutacion.alquimista_id} - Material {transmutacion.material_id} - Estado: {transmutacion.estado} - Costo: {transmutacion.costo}
                {transmutacion.resultado && ` - Resultado: ${transmutacion.resultado}`}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2>Auditorías</h2>
        {auditorias.length === 0 ? (
          <p>No hay auditorías registradas.</p>
        ) : (
          <ul>
            {auditorias.map((auditoria) => (
              <li key={auditoria.id}>
                [{new Date(auditoria.created_at).toLocaleString()}] {auditoria.tipo} - {auditoria.detalle}
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
};

export default Supervisor;

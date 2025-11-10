import { useEffect, useMemo, useState } from 'react';
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

type Material = {
  id: number;
  nombre: string;
  stock: number;
};

const Supervisor = () => {
  const navigate = useNavigate();
  const [transmutaciones, setTransmutaciones] = useState<Transmutacion[]>([]);
  const [auditorias, setAuditorias] = useState<Auditoria[]>([]);
  const [materiales, setMateriales] = useState<Material[]>([]);
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
        const [transmutacionesData, auditoriasData, materialesData] = await Promise.all([
          apiFetch<Transmutacion[]>('/transmutaciones'),
          apiFetch<Auditoria[]>('/auditorias'),
          apiFetch<Material[]>('/materiales'),
        ]);

        if (!active) {
          return;
        }

        setTransmutaciones(transmutacionesData);
        setAuditorias(auditoriasData);
        setMateriales(materialesData);
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

  const resumenEstados = useMemo(() => {
    return transmutaciones.reduce<Record<string, number>>((acc, transmutacion) => {
      acc[transmutacion.estado] = (acc[transmutacion.estado] ?? 0) + 1;
      return acc;
    }, {});
  }, [transmutaciones]);

  const usoMateriales = useMemo(() => {
    const materialPorId = new Map(materiales.map((material) => [material.id, material.nombre] as const));
    return transmutaciones.reduce<Record<string, number>>((acc, transmutacion) => {
      const nombre = materialPorId.get(transmutacion.material_id) ?? `Material ${transmutacion.material_id}`;
      acc[nombre] = (acc[nombre] ?? 0) + 1;
      return acc;
    }, {});
  }, [materiales, transmutaciones]);

  return (
    <main>
      <h1>Panel de Supervisor</h1>

      {error && <p role="alert">{error}</p>}

      <section>
        <h2>Resumen de transmutaciones</h2>
        {Object.keys(resumenEstados).length === 0 ? (
          <p>No hay transmutaciones registradas.</p>
        ) : (
          <ul>
            {Object.entries(resumenEstados).map(([estado, total]) => (
              <li key={estado}>
                {estado}: {total}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2>Uso de materiales</h2>
        {Object.keys(usoMateriales).length === 0 ? (
          <p>Aún no se registraron consumos de materiales.</p>
        ) : (
          <ul>
            {Object.entries(usoMateriales).map(([nombre, total]) => (
              <li key={nombre}>
                {nombre}: {total} transmutaciones
              </li>
            ))}
          </ul>
        )}
      </section>

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

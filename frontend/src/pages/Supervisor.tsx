import { useCallback, useEffect, useMemo, useState } from 'react';
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

  const loadData = useCallback(
    async (options?: { shouldIgnore?: () => boolean }) => {
      const [transmutacionesData, auditoriasData, materialesData] = await Promise.all([
        apiFetch<Transmutacion[]>('/transmutaciones'),
        apiFetch<Auditoria[]>('/auditorias'),
        apiFetch<Material[]>('/materiales'),
      ]);

      if (options?.shouldIgnore?.()) {
        return;
      }

      setTransmutaciones(transmutacionesData);
      setAuditorias(auditoriasData);
      setMateriales(materialesData);
    },
    []
  );

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

    let ignore = false;

    loadData({ shouldIgnore: () => ignore }).catch((err) => {
      if (!ignore) {
        setError((err as Error).message);
      }
    });

    return () => {
      ignore = true;
    };
  }, [loadData, navigate]);

  const resumenGeneral = useMemo(() => {
    let aprobadas = 0;
    let pendientes = 0;
    let rechazadas = 0;

    for (const transmutacion of transmutaciones) {
      switch (transmutacion.estado) {
        case 'aprobada':
          aprobadas += 1;
          break;
        case 'pendiente':
        case 'procesando':
          pendientes += 1;
          break;
        case 'rechazada':
          rechazadas += 1;
          break;
        default:
          break;
      }
    }

    return {
      total: transmutaciones.length,
      aprobadas,
      pendientes,
      rechazadas,
    };
  }, [transmutaciones]);

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

  const totalAuditorias = auditorias.length;

  const gestionarTransmutacion = async (id: number, accion: 'aprobar' | 'rechazar') => {
    try {
      await apiFetch(`/transmutaciones/${id}/${accion}`, { method: 'POST' });
      await loadData();
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <main>
      <h1>Panel de Supervisor</h1>

      {error && <p role="alert">{error}</p>}

      <section>
        <h2>Resumen</h2>
        <ul>
          <li>Total de transmutaciones: {resumenGeneral.total}</li>
          <li>Transmutaciones aprobadas: {resumenGeneral.aprobadas}</li>
          <li>Transmutaciones pendientes/procesando: {resumenGeneral.pendientes}</li>
          <li>Transmutaciones rechazadas: {resumenGeneral.rechazadas}</li>
          <li>Total de auditorías: {totalAuditorias}</li>
        </ul>
      </section>

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
                {(transmutacion.estado === 'pendiente' || transmutacion.estado === 'procesando') && (
                  <span>
                    {' '}
                    <button type="button" onClick={() => gestionarTransmutacion(transmutacion.id, 'aprobar')}>
                      Aprobar
                    </button>
                    {' '}
                    <button type="button" onClick={() => gestionarTransmutacion(transmutacion.id, 'rechazar')}>
                      Rechazar
                    </button>
                  </span>
                )}
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

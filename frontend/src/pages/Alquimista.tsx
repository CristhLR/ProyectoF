import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiFetch } from '../api/client.ts';

type User = {
  id: number;
  nombre: string;
  rango: string;
};

type Mision = {
  id: number;
  titulo: string;
  estado: string;
  alquimista_id: number;
};

type Material = {
  id: number;
  nombre: string;
  stock: number;
};

type Transmutacion = {
  id: number;
  alquimista_id: number;
  material_id: number;
  estado: string;
  costo: number;
  resultado?: string;
};

const Alquimista = () => {
  const navigate = useNavigate();
  const user = useMemo<User | null>(() => {
    if (typeof window === 'undefined') {
      return null;
    }

    const stored = localStorage.getItem('user');
    if (!stored) {
      return null;
    }

    try {
      return JSON.parse(stored) as User;
    } catch (err) {
      console.error('No se pudo parsear el usuario almacenado', err);
      return null;
    }
  }, []);

  const [misiones, setMisiones] = useState<Mision[]>([]);
  const [materiales, setMateriales] = useState<Material[]>([]);
  const [transmutaciones, setTransmutaciones] = useState<Transmutacion[]>([]);
  const [selectedMaterial, setSelectedMaterial] = useState('');
  const [costo, setCosto] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchTransmutaciones = useCallback(async () => {
    if (!user) {
      return;
    }

    const data = await apiFetch<Transmutacion[]>('/transmutaciones');
    setTransmutaciones(data.filter((item) => item.alquimista_id === user.id));
  }, [user]);

  useEffect(() => {
    if (!user) {
      navigate('/login', { replace: true });
      return;
    }

    let active = true;

    const loadData = async () => {
      try {
        const [misionesData, materialesData] = await Promise.all([
          apiFetch<Mision[]>('/misiones'),
          apiFetch<Material[]>('/materiales'),
        ]);

        if (!active) {
          return;
        }

        setMisiones(misionesData.filter((mision) => mision.alquimista_id === user.id));
        setMateriales(materialesData);
        await fetchTransmutaciones();
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
  }, [fetchTransmutaciones, navigate, user]);

  useEffect(() => {
    const socket = new WebSocket('ws://localhost:8080/ws/notificaciones');

    socket.onmessage = (event) => {
      alert(event.data);
    };

    socket.onerror = () => {
      console.error('Error en la conexión de WebSocket');
    };

    return () => {
      socket.close();
    };
  }, []);

  const handleCreateTransmutacion = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!user) {
      navigate('/login', { replace: true });
      return;
    }

    if (!selectedMaterial || !costo) {
      setError('Selecciona un material e ingresa un costo');
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const costoValue = parseFloat(costo);
      const nueva = await apiFetch<Transmutacion>('/transmutaciones', {
        method: 'POST',
        body: JSON.stringify({
          alquimista_id: user.id,
          material_id: Number(selectedMaterial),
          costo: costoValue,
        }),
      });

      setTransmutaciones((prev) => [...prev, nueva]);
      setSelectedMaterial('');
      setCosto('');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleProcesar = async (id: number) => {
    setError(null);
    try {
      await apiFetch(`/transmutaciones/${id}/procesar`, { method: 'POST' });
      await fetchTransmutaciones();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const obtenerNombreMaterial = (materialId: number) => {
    const material = materiales.find((item) => item.id === materialId);
    return material ? material.nombre : `Material ${materialId}`;
  };

  return (
    <main>
      <h1>Panel del Alquimista</h1>

      {error && <p role="alert">{error}</p>}

      <section>
        <h2>Mis misiones</h2>
        {misiones.length === 0 ? (
          <p>No tienes misiones asignadas.</p>
        ) : (
          <ul>
            {misiones.map((mision) => (
              <li key={mision.id}>
                {mision.titulo} - Estado: {mision.estado}
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2>Materiales disponibles</h2>
        {materiales.length === 0 ? (
          <p>No hay materiales registrados.</p>
        ) : (
          <ul>
            {materiales.map((material) => (
              <li key={material.id}>
                {material.nombre} (stock: {material.stock})
              </li>
            ))}
          </ul>
        )}
      </section>

      <section>
        <h2>Nueva transmutación</h2>
        <form onSubmit={handleCreateTransmutacion}>
          <div>
            <label htmlFor="material">Material</label>
            <select
              id="material"
              value={selectedMaterial}
              onChange={(event) => setSelectedMaterial(event.target.value)}
              required
            >
              <option value="">Selecciona un material</option>
              {materiales.map((material) => (
                <option key={material.id} value={material.id}>
                  {material.nombre}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="costo">Costo</label>
            <input
              id="costo"
              type="number"
              min="0"
              step="0.01"
              value={costo}
              onChange={(event) => setCosto(event.target.value)}
              required
            />
          </div>
          <button type="submit" disabled={loading}>
            {loading ? 'Creando...' : 'Crear transmutación'}
          </button>
        </form>
      </section>

      <section>
        <h2>Mis transmutaciones</h2>
        {transmutaciones.length === 0 ? (
          <p>Todavía no creaste transmutaciones.</p>
        ) : (
          <ul>
            {transmutaciones.map((transmutacion) => (
              <li key={transmutacion.id}>
                #{transmutacion.id} - {obtenerNombreMaterial(transmutacion.material_id)} - Estado: {transmutacion.estado}
                <button
                  type="button"
                  onClick={() => handleProcesar(transmutacion.id)}
                  disabled={transmutacion.estado !== 'pendiente'}
                >
                  Procesar
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
};

export default Alquimista;

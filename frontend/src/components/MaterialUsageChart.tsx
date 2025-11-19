import React, { useEffect, useState } from "react";
import { apiFetch } from "../api/client.ts";

type Material = {
  id: number;
  nombre: string;
  stock: number;
};

type Transmutacion = {
  id: number;
  material_id: number;
};

type Row = {
  id: number;
  nombre: string;
  stock: number;
  usos: number;
};

const MaterialUsageChart: React.FC = () => {
  const [rows, setRows] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        setError(null);

        const [materiales, transmutaciones] = await Promise.all([
          apiFetch<Material[]>("/materiales"),
          apiFetch<Transmutacion[]>("/transmutaciones"),
        ]);

        const usosPorMaterial: Record<number, number> = {};
        for (const t of transmutaciones) {
          usosPorMaterial[t.material_id] =
            (usosPorMaterial[t.material_id] || 0) + 1;
        }

        const merged: Row[] = materiales.map((m) => ({
          id: m.id,
          nombre: m.nombre,
          stock: m.stock,
          usos: usosPorMaterial[m.id] || 0,
        }));

        // ordenar por más usados
        merged.sort((a, b) => b.usos - a.usos);

        setRows(merged);
      } catch (err: unknown) {
        if (err instanceof Error) {
          setError(err.message || "No se pudo cargar la gráfica de materiales");
        } else {
          setError("No se pudo cargar la gráfica de materiales");
        }
      } finally {
        setLoading(false);
      }
    };

    load();
  }, []);

  if (loading) {
    return (
      <section style={{ marginBottom: "1.5rem" }}>
        <h2>Uso de materiales (gráfico)</h2>
        <p>Cargando...</p>
      </section>
    );
  }

  if (error) {
    return (
      <section style={{ marginBottom: "1.5rem" }}>
        <h2>Uso de materiales (gráfico)</h2>
        <p style={{ color: "red" }}>{error}</p>
      </section>
    );
  }

  const maxUsos = rows.reduce((max, r) => (r.usos > max ? r.usos : max), 0);

  return (
    <section style={{ marginBottom: "1.5rem" }}>
      <h2>Uso de materiales (gráfico)</h2>
      {rows.length === 0 ? (
        <p>No hay materiales.</p>
      ) : (
        <div style={{ display: "grid", gap: "0.75rem", marginTop: "0.75rem" }}>
          {rows.map((row) => {
            const percent = maxUsos === 0 ? 0 : (row.usos / maxUsos) * 100;
            return (
              <div
                key={row.id}
                style={{
                  display: "grid",
                  gridTemplateColumns: "minmax(0, 1fr) 3fr auto",
                  gap: "0.5rem",
                  alignItems: "center",
                }}
              >
                <span>
                  {row.nombre}{" "}
                  <span style={{ color: "#6b7280", fontSize: "0.75rem" }}>
                    (stock: {row.stock})
                  </span>
                </span>
                <div
                  aria-hidden="true"
                  style={{
                    backgroundColor: "#e5e7eb",
                    height: "0.75rem",
                    borderRadius: "9999px",
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      width: `${percent}%`,
                      backgroundColor: "#6366f1",
                      height: "100%",
                      borderRadius: "9999px",
                      transition: "width 150ms ease-out",
                    }}
                  />
                </div>
                <span>{row.usos}</span>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
};

export default MaterialUsageChart;

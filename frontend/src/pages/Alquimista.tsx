import { Link } from 'react-router-dom';

const Alquimista = () => {
  return (
    <main>
      <h1>Alquimista</h1>
      <nav>
        <Link to="/supervisor">Ir a Supervisor</Link>
      </nav>
    </main>
  );
};

export default Alquimista;

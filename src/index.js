import app from "./app.js";
import { PORT } from "./config.js";
import { connectDB } from "./db.js";

// Función principal para arrancar la aplicación
async function main() {
  try {
    await connectDB(); // Conecta a la base de datos
    app.listen(PORT); // Inicia el servidor
    console.log(`Listening on port http://localhost:${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV}`)
  } catch (error) {
    console.error(error);
  }
}

main();

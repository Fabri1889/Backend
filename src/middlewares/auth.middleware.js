import jwt from "jsonwebtoken";
import { TOKEN_SECRET } from "../config.js";

// Middleware para verificar la autenticación del usuario
export const auth = (req, res, next) => {
  try {
    const { token } = req.cookies;

    if (!token)
      return res
        .status(401)
        .json({ message: "No token, authorization denied" });

    jwt.verify(token, TOKEN_SECRET, (error, user) => {
      if (error) {
        return res.status(401).json({ message: "Token is not valid" });
      }
      req.user = user; // Agrega los datos del usuario al objeto request
      next(); // Pasa al siguiente middleware
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
};

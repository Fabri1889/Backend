import { z } from "zod";

export const registerSchema = z.object({
  username: z.string({
    required_error: "Usuario es requerido",
  }),
  email: z
    .string({
      required_error: "Email es requerido",
    })
    .email({
      message: "Email no es valido",
    }),
  password: z
    .string({
      required_error: "Contraseña incorrecta",
    })
    .min(6, {
      message: "La contraseña debe ser mayor a 6 caracteres",
    }),
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

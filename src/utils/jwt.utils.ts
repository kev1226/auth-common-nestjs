// src/utils/jwt.utils.ts
import jwt from "jsonwebtoken";

const SECRET_KEY = "kalemat2025";

export const verifyToken = (token: string) => {
  try {
    return jwt.verify(token, SECRET_KEY);
  } catch (error) {
    return null;
  }
};

export const decodeToken = (token: string) => {
  try {
    return jwt.decode(token);
  } catch (error) {
    return null;
  }
};

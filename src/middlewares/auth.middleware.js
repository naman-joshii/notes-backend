import jwt from "jsonwebtoken";
import User from "../models/user.model.js";
import dotenv from "dotenv";

dotenv.config();

export const protectedRoute = async (req, res, next) => {
  try {
    const token = req.cookies.jwt;
    if (!token) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Decoded token payload:", decoded);

    const userId = decoded.userId || decoded.id; // ✅ FIXED HERE

    const user = await User.findById(userId).select("-password");
    if (!user) {
      return res.status(404).json({ message: "Unauthorized" });
    }

    req.user = user;
    next();

  } catch (error) {
    console.error("Error in protectedRoute:", error.message);

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: "Invalid token" });
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: "Token expired" });
    }

    res.status(500).json({ message: "Internal server error" });
  }
};

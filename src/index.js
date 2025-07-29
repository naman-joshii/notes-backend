import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";

import { connectDB } from "./lib/db.js";

import authRoutes from "./routes/auth.route.js";
import noteRoutes from "./routes/note.route.js";

dotenv.config();
const app = express();
const PORT = process.env.PORT;

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: "http://localhost:5173",
    credentials: true,
}));

app.use("/api/auth", authRoutes);
app.use("/api/notes", noteRoutes);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log("email pass: ", process.env.EMAIL_PASS);
    console.log("email user: ", process.env.EMAIL_USER);
    connectDB();
});

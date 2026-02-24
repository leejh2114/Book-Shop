import express from "express";
import { getAllCategory } from "../controller/categoryController.js";

const router = express.Router();

router.get("/", getAllCategory);

export default router;
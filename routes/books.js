import express from "express";
import { getAllbooks, getBookById } from "../controller/bookController.js";

const router = express.Router();

router
  .get("/", getAllbooks)

  .get("/:id", getBookById);

export default router;
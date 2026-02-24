import express from "express";
import { addLike, removeLike } from "../controller/likeController.js";
const router = express.Router();

router
  .post("/:liked_book_id", addLike)

  .delete("/:liked_book_id", removeLike);

export default router;
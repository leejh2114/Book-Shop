import express from "express";
import {
  addCart,
  getCartItems,
  deleteCartItem,
} from "../controller/cartController.js";
const router = express.Router();

router
  .post("/", addCart)

  .get("/", getCartItems)

  .delete("/:cart_id", deleteCartItem);

export default router;
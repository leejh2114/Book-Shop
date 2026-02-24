import express from "express";

const router = express.Router();

router
  .post("/", (req, res) => {
    res.json("주문하기");
  })
  .get("/", (req, res) => {
    res.json("주문 목록 조회");
  })
  .get("/:id", (req, res) => {
    res.json("주문 상세 상품 조회");
  });

export default router;
import conn from "../db/mysql_connect.js";
import { StatusCodes } from "http-status-codes";

export const addCart = (req, res) => {
  const { book_id, quantity, user_id } = req.body;

  const sql = "INSERT INTO cart (book_id, quantity, user_id) VALUES (?, ?, ?)";
  const values = [book_id, quantity, user_id];

  conn.query(sql, values, (err, results) => {
    if (err) {
      console.error("장바구니 담기 DB 에러:", err);
      return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(err);
    }
    return res.status(StatusCodes.CREATED).json(results);
  });
};

export const getCartItems = (req, res) => {
  const { user_id, selected } = req.body;

  let sql = `
    SELECT 
        cart.cart_id, 
        cart.book_id, 
        books.title, 
        books.summary, 
        cart.quantity, 
        books.price 
    FROM cart 
    LEFT JOIN books ON cart.book_id = books.book_id
    WHERE cart.user_id = ?`;

  let values = [user_id];
  if (selected && selected.length > 0) {
    sql += ` AND cart.cart_id IN (?)`;
    values.push(selected);
  }

  conn.query(sql, values, (err, results) => {
    if (err) {
      console.error("장바구니 조회 DB 에러:", err);
      return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(err);
    }
    return res.status(StatusCodes.OK).json(results);
  });
};

export const deleteCartItem = (req, res) => {
  const { cart_id } = req.params;

  const sql = "DELETE FROM cart WHERE cart_id = ?";
  const values = [cart_id];

  conn.query(sql, values, (err, results) => {
    if (err) {
      console.error("장바구니 삭제 DB 에러:", err);
      return res.status(StatusCodes.INTERNAL_SERVER_ERROR).end();
    }
    return res.status(StatusCodes.OK).json({
      message: "장바구니 삭제 성공",
      results,
    });
  });
};
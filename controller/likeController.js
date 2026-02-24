import conn from "../db/mysql_connect.js";
import { StatusCodes } from "http-status-codes";

export const addLike = (req, res) => {
  const { liked_book_id } = req.params;
  const { user_id } = req.body;

  const sql = "INSERT INTO likes (user_id, liked_book_id) VALUES (?, ?)";
  const values = [user_id, liked_book_id];

  conn.query(sql, values, function (err, results) {
    if (err) {
      console.error("좋아요 추가 DB 에러:", err);
      return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(err);
    }
    return res.status(StatusCodes.CREATED).json({
      message: "좋아요 성공!",
      result: results,
    });
  });
};

export const removeLike = (req, res) => {
  const { liked_book_id } = req.params;
  const { user_id } = req.body;

  const sql = "DELETE FROM likes WHERE user_id = ? AND liked_book_id = ?";
  const values = [user_id, liked_book_id];

  conn.query(sql, values, function (err, results) {
    if (err) {
      console.error("좋아요 삭제 DB 에러:", err);
      return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(err);
    }
    return res.status(StatusCodes.CREATED).json({
      message: "좋아요 삭제 성공!",
      result: results,
    });
  });
};
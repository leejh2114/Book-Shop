import conn from "../db/mysql_connect.js";
import { StatusCodes } from "http-status-codes";

export const getAllCategory = (req, res) => {
  const sql = `SELECT * FROM category`;

  conn.query(sql, (err, results) => {
    if (err) {
      console.error("카테고리 전체 조회 요청 DB 에러:", err);
      return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(err);
    }
    return res.status(StatusCodes.OK).json(results);
  });
};
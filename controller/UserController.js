import conn from "../db/mysql_connect.js";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { StatusCodes } from "http-status-codes";

// 회원가입
export const join = (req, res) => {
  const { email, name, password } = req.body;

  const salt = crypto.randomBytes(10).toString("base64");

  const hashPassword = crypto
    .pbkdf2Sync(password, salt, 10000, 10, "sha512")
    .toString("base64");

  const sql = `INSERT INTO users (email, name, password, salt) VALUES (?, ?, ?, ?)`;
  const values = [email, name, hashPassword, salt];

  conn.query(sql, values, function (err, results) {
    if (err) {
      console.error("회원가입 DB 에러:", err);
      return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(err);
    }
    return res.status(StatusCodes.CREATED).json({
      message: "회원가입 성공!",
      result: results,
    });
  });
};

// 로그인
export const login = (req, res) => {
  const { email, password } = req.body;
  const sql = `SELECT * FROM users WHERE email = ?`;

  conn.query(sql, [email], (err, results) => {
    if (err) {
      console.error("로그인 DB 에러:", err);
      return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(err);
    }

    const loginUser = results[0];

    if (loginUser) {
      const hashPassword = crypto
        .pbkdf2Sync(password, loginUser.salt, 10000, 10, "sha512")
        .toString("base64");

      if (loginUser.password === hashPassword) {
        const token = jwt.sign(
          {
            email: loginUser.email,
            name: loginUser.name,
          },
          process.env.JWT_SECRET_KEY,
          {
            expiresIn: "3m",
            issuer: "kyuhyun",
          },
        );

        res.cookie("token", token, {
          httpOnly: true,
        });

        return res.status(StatusCodes.OK).json({
          message: `${loginUser.name}님, 환영합니다!`,
        });
      }
    }
    return res.status(StatusCodes.UNAUTHORIZED).json({
      message: "아이디 또는 비밀번호가 틀렸습니다.",
    });
  });
};

// 비밀번호 초기화 요청
export const pwdResetReq = (req, res) => {
  const { email } = req.body;
  const sql = `SELECT * FROM users WHERE email = ?`;

  conn.query(sql, [email], (err, results) => {
    if (err) {
      console.error("비밀번호 초기화 요청 DB 에러:", err);
      return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(err);
    }

    const user = results[0];
    if (user) {
      return res.status(StatusCodes.OK).json({
        email: email,
        message: "비밀번호를 변경할 준비가 되었습니다.",
      });
    } else {
      return res.status(StatusCodes.UNAUTHORIZED).json({
        message: "해당 이메일로 가입된 정보가 없습니다.",
      });
    }
  });
};

// 비밀번호 초기화
export const pwdReset = (req, res) => {
  const { email, password } = req.body;

  const salt = crypto.randomBytes(10).toString("base64");

  const hashPassword = crypto
    .pbkdf2Sync(password, salt, 10000, 10, "sha512")
    .toString("base64");

  const sql = `UPDATE Users SET password = ?, salt = ? WHERE email = ?`;
  const values = [hashPassword, salt, email];

  conn.query(sql, values, (err, results) => {
    if (err) {
      console.error("비밀번호 변경 DB 에러:", err);
      return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(err);
    }

    if (results.affectedRows === 0) {
      return res.status(StatusCodes.BAD_REQUEST).json({
        message: "비밀번호 변경에 실패했습니다.",
      });
    }

    return res.status(StatusCodes.OK).json({
      message: "비밀번호가 성공적으로 변경되었습니다.",
    });
  });
};
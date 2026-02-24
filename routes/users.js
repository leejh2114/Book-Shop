import express from "express";
import { body } from "express-validator";
import { validator } from "../middleware/validator.js";
import {
  join,
  login,
  pwdResetReq,
  pwdReset,
} from "../controller/userController.js";

const router = express.Router();

router
  .post(
    "/join",
    [
      body("email").notEmpty().isEmail().withMessage("이메일을 확인해주세요."),
      body("name").notEmpty().isString().withMessage("이름을 확인해주세요."),
      body("password")
        .notEmpty()
        .isString()
        .withMessage("비밀번호를 확인해주세요."),
    ],
    validator,
    join,
  )

  .post(
    "/login",
    [
      body("email")
        .notEmpty()
        .isEmail()
        .withMessage("올바른 이메일 형식이 아닙니다."),
      body("password")
        .notEmpty()
        .isString()
        .withMessage("비밀번호를 입력해주세요."),
    ],
    validator,
    login,
  )

  .post(
    "/reset",
    [body("email").notEmpty().isEmail().withMessage("이메일을 입력해주세요.")],
    validator,
    pwdResetReq,
  )

  .put(
    "/reset",
    [
      body("email").notEmpty().isEmail().withMessage("이메일을 입력해주세요."),
      body("password")
        .notEmpty()
        .isString()
        .withMessage("새로운 비밀번호를 입력해주세요."),
    ],
    validator,
    pwdReset,
  );

export default router;
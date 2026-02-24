import mysql from "mysql2";
import dotenv from "dotenv";

dotenv.config();

const conn = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  dateStrings: true,
});

conn.connect((err) => {
  if (err) console.error("❌ DB 연결 실패:", err.message);
  else console.log("✅ DB 연결 성공!");
});

export default conn;
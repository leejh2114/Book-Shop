const conn = require('../mariadb');
const {StatusCodes} = require('http-status-codes');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

const join = (req, res) => {
    const {email, password} = req.body;

    let sql = 'INSERT INTO users (email, password) VALUES (?, ?)';
    let VALUES = [email, password];

    conn.query(sql, VALUES,
        (err, results) => {
            if(err) {
                console.log(err);
                return res.status(StatusCodes.BAD_REQUEST).end();
            }

            return res.status(StatusCodes.BAD_REQUEST).json(results);
        })
};

const login = (req, res) => {
    const {email, password} = req.body;

    let sql ='SELECT * FROM users WHERE email = ?';
    conn.query(sql, email,
        (err, results)=> {
            if(err){
                console.log(err);
                return res.status(StatusCodes.BAD_REQUEST).end();
            }

            const loginUser = results[0];
            if(loginUser && loginUser.password == password){
                //토큰 발행
                const token = jwt.sign({
                    email : loginUser.email
                }, process.env.PRIVATE_KEY,{
                    expiresIn : '5m',
                    issuer : "junhyun"
                });

                //토큰 쿠키에 담기
                res.cookie("token", token,{
                    httpOnly : true
                });
                console.log(token);

                return res.status(StatusCodes.OK).json(results);
            } else {
                return res.status(StatusCodes.UNAUTHORIZED).end();
            }            
        }
    )
};

const passwordReset = (req, res) => {
    res.json('비밀번호 초기화');
};

const requestPasswordReset = (req, res) => {
    res.json('비밀번호 초기화');
};



module.exports = {
    join,
    login,
    requestPasswordReset,
    passwordReset
};
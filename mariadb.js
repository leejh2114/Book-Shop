//mysql 모듈 소환
const mariadb = require('mysql2');

//db와 연결 통로 생성
const connection = mariadb.createConnection({
    host : '127.0.0.1',
    user : 'root',
    passwors : 'root',
    database : 'Bookshop',
    dataStrings : true
});

module.exports = connection;
-- users id 컬럼명 변경 --
ALTER TABLE users CHANGE COLUMN id user_id INT NOT NULL AUTO_INCREMENT;

--  books id 컬럼명 변경 --
ALTER TABLE books CHANGE COLUMN id book_id INT NOT NULL AUTO_INCREMENT;
-- 예약어로 인한 컬럼명 수정 --
ALTER TABLE books CHANGE COLUMN `format` form VARCHAR(45) NOT NULL;
ALTER TABLE books CHANGE COLUMN `description` detail LONGTEXT NULL;
ALTER TABLE books CHANGE COLUMN `index` contents LONGTEXT NULL;
-- 컬럼 추가--
ALTER TABLE books ADD COLUMN img INT NULL AFTER title;
ALTER TABLE books ADD COLUMN category_id INT NULL AFTER img;

-- categoty_id 컬럼 수정 --
ALTER TABLE books ADD INDEX category_id_idx (`category_id` ASC);
ALTER TABLE books ADD CONSTRAINT category_id FOREIGN KEY (category_id) REFERENCES category (id);
-- pub_date 수정 --
UPDATE books SET pub_date = '2026-02-15' WHERE book_id = 11;
UPDATE books SET pub_date = '2026-02-05' WHERE book_id = 10;
UPDATE books SET pub_date = '2026-01-25' WHERE book_id = 9;
UPDATE books SET pub_date = '2026-01-19' WHERE book_id = 8;
UPDATE books SET pub_date = '2025-11-20' WHERE book_id = 7;
UPDATE books SET pub_date = '2025-02-10' WHERE book_id = 6;
UPDATE books SET pub_date = '2024-06-15' WHERE book_id = 5;

-- id 컬럼명 변경 --
ALTER TABLE category CHANGE COLUMN id category_id INT NOT NULL;
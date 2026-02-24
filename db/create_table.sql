-- 유저 테이블 생성 --
CREATE TABLE users (
  id INT NOT NULL AUTO_INCREMENT,
  email VARCHAR(100) NOT NULL,
  name VARCHAR(45) NOT NULL,
  password VARCHAR(45) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `email_UNIQUE` (`email` ASC)
);

-- 도서 테이블 생성 --
CREATE TABLE `books` (
  id INT NOT NULL AUTO_INCREMENT,
  title VARCHAR(45) NOT NULL,
  `format` VARCHAR(45) NOT NULL,
  isbn VARCHAR(45) NOT NULL,
  summary VARCHAR(500) NULL,
  `description` LONGTEXT NULL,
  author VARCHAR(45) NOT NULL,
  pages INT NOT NULL,
  `index` LONGTEXT NULL,
  price INT NOT NULL,
  pub_date DATE NULL,
  PRIMARY KEY (`id`),
  UNIQUE INDEX `isbn_UNIQUE` (`isbn` ASC)
);

-- 카테고리 테이블 생성 --
CREATE TABLE category (
  id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  PRIMARY KEY(id)
);

-- 좋아요 테이블 생성 --
CREATE TABLE likes (
  user_id INT NOT NULL,
  liked_book_id INT NOT NULL,

  INDEX user_id_idx (`user_id` ASC),
  INDEX liked_book_id_idx (`liked_book_id` ASC),

  CONSTRAINT fk_likes_user
    FOREIGN KEY (`user_id`)
    REFERENCES users (`user_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION,

  CONSTRAINT `fk_likes_book`
    FOREIGN KEY (`liked_book_id`)
    REFERENCES books (`book_id`)
    ON DELETE CASCADE
    ON UPDATE NO ACTION
)

-- 장바구니 테이블 생성 --
CREATE TABLE cart (
    cart_id INT NOT NULL AUTO_INCREMENT,
    book_id INT NOT NULL,
    user_id INT NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    PRIMARY KEY (cart_id),
    
    INDEX book_id_idx (book_id ASC),
    INDEX user_id_idx (user_id ASC),

    CONSTRAINT fk_cart_book 
      FOREIGN KEY (book_id) 
      REFERENCES books (book_id) 
      ON DELETE CASCADE,
      
    CONSTRAINT fk_cart_user 
      FOREIGN KEY (user_id) 
      REFERENCES users (user_id) 
      ON DELETE CASCADE
);
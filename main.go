package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var TOKEN_SECRET string = "mySecret"

type JwtClaims struct {
	Id int `json:"id"`
	jwt.StandardClaims
}

type UserHandler struct {
	DB *sql.DB
}

type Userhotel struct {
	Id            uint   `sql:"primary_key" json:"id" form:"id" query:"id"`
	Email         string `json:"email" form:"email" query:"email"`
	Password      string `json:"password" form:"password" query:"password"`
	Firstname     string `json:"firstname" form:"firstname" query:"firstname"`
	Lastname      string `json:"lastname" form:"lastname" query:"lastname"`
	Birthday      string `json:"birthday" form:"birthday" query:"birthday"`
	Tel           string `json:"tel" form:"tel" query:"tel"`
	Create_by     int    `json:"create_by" form:"create_by" query:"create_by"`
	Update_by     int    `json:"update_by" form:"update_by" query:"update_by"`
	Userpermis_id int    `json:"userpermis_id" form:"userpermis_id" query:"userpermis_id"`
}

type Booking struct {
	ID          uint   `sql:"primary_key" json:"id" form:"id" query:"id"`
	User_id     int    `json:"User_id" form:"User_id" query:"User_id"`
	Create_from string `json:"create_from" form:"create_from" query:"create_from"`
	Create_to   string `json:"create_to" form:"create_to" query:"create_to"`
	Room_id     int    `json:"room_id" form:"room_id" query:"room_id"`
	Active_id   int    `json:"active_id" from:"active_id" query:"active_id"`
}

type UserCheck struct {
	Id            uint   `sql:"primary_key" json:"id" form:"id" query:"id"`
	Email         string `json:"email" form:"email" query:"email"`
	Firstname     string `json:"firstname" form:"firstname" query:"firstname"`
	Tel           string `json:"tel" form:"tel" query:"tel"`
	Lastname      string `json:"lastname" form:"lastname" query:"lastname"`
	Birthday      string `json:"birthday" form:"birthday" query:"birthday"`
	Userpermis_id int    `json:"userpermis_id" form:"userpermis_id" query:"userpermis_id"`
}

type Room struct {
	Id             uint   `sql:"primary_key" json:"id" form:"id" query:"id"`
	Create_by_user int    `json:"create_by_user" form:"create_by_user" query:"create_by_user"`
	Name_room      string `json:"name_room" form:"name_room" query:"name_room"`
	Room_type_id   int    `json:"room_type_id" form:"room_type_id" query:"room_type_id"`
	Price          int    `json:"price" form:"price" query:"price"`
	Detail         string `json:"detail" form:"detail" query:"detail"`
}

type Total struct {
	Id    int `sql:"primary_key" json:"id" form:"id" query:"id"`
	Total int `json:"total" form:"total" query:"total"`
}

func (h *UserHandler) Initialize() {
	// connStr := "postgres://postgres:sanchai@34.87.1.245/demolab?sslmode=disable"
	conStr2 := "postgres://sanchaipengboot:sanchai@localhost/sanchaipengboot?sslmode=disable"
	db, err := sql.Open("postgres", conStr2)
	if err != nil {
		log.Println(err)
	}
	h.DB = db
}

func (h *UserHandler) login(c echo.Context) (err error) {

	data := new(Userhotel)

	//get email, passwrod form request(body)
	body, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {
		log.Println(err)
	}

	json.Unmarshal(body, &data)

	email := data.Email
	password := data.Password

	//select password by email
	rows, err := h.DB.Prepare("SELECT id, email, password, userpermis_id,firstname  FROM userhotel WHERE email=$1  ")
	if err != nil {
		log.Println(err)
	}

	defer rows.Close()

	//for rows.Next() { //Next ดึงหลาย rows  ถ้าจะดึงrows เดียวใช้อันไหน

	//แสดงข้อมูลที่ selcet ออกมา
	err = rows.QueryRow(email).Scan(&data.Id, &data.Email, &data.Password, &data.Userpermis_id, &data.Firstname)
	if err != nil {
		log.Println("Scan failed:", err.Error())
	}

	//verify password by bcrypt
	// data.Password มาเช็คว่า password เป็นค่าเดียวกันหรือไม่
	err = bcrypt.CompareHashAndPassword([]byte(data.Password), []byte(password))
	if err != nil {
		return c.String(http.StatusUnauthorized, "Your Email or Password were wrong")
	}

	// check email and password against DB after hashing the password
	if data.Userpermis_id == 1 {
		log.Println(data.Firstname)
		// create jwt token
		token, err := createJwtToken(int(data.Id)) //ควรเก็บ id and userpermis
		if err != nil {
			log.Println("Error Creating JWT token", err)
			return c.String(http.StatusInternalServerError, "something went wrong")
		}

		cookie := new(http.Cookie)
		cookie.Name = "cookie_login"
		cookie.Value = token
		cookie.Expires = time.Now().Add(24 * time.Hour)
		cookie.HttpOnly = true

		c.SetCookie(cookie)

		return c.JSON(http.StatusOK, map[string]string{
			"firstname": data.Firstname,
			"email":     data.Email,
			"type":      "Admin",
			"message":   "success",
			"token":     token,
			"tel":       data.Tel,
			"birthday":  data.Birthday,
		})

	} else if data.Userpermis_id == 2 {

		// create jwt token

		token, err := createJwtToken(int(data.Id)) //ควรเก็บ id and userpermis
		if err != nil {
			log.Println("Error Creating JWT token", err)
			return c.String(http.StatusInternalServerError, "something went wrong")
		}

		cookie := new(http.Cookie)
		cookie.Name = "cookie_login"
		cookie.Value = token
		cookie.Expires = time.Now().Add(24 * time.Hour)
		cookie.HttpOnly = true
		c.SetCookie(cookie)

		return c.JSON(http.StatusOK, map[string]string{
			"firstname": data.Firstname,
			"email":     data.Email,
			"type":      "Admin",
			"message":   "success",
			"token":     token,
			"tel":       data.Tel,
			"birthday":  data.Birthday,
		})

	}

	return c.String(http.StatusUnauthorized, "Your Email or Password were wrong")
}

func createJwtToken(id int) (string, error) {

	claims := JwtClaims{
		id,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
	}

	rawToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := rawToken.SignedString([]byte(TOKEN_SECRET))

	if err != nil {

		return "", err

	}

	return token, nil
}

func ValidateToken(token string) (JwtClaims, error) {

	t, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, isvalid := token.Method.(*jwt.SigningMethodHMAC); !isvalid {
			return nil, fmt.Errorf("Invalid token %s", token.Header["alg"])

		}
		return []byte(TOKEN_SECRET), nil
	})

	var result JwtClaims
	if claims, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
		result.Id = int(claims["id"].(float64))
		return result, nil

	} else {
		return result, err
	}

}

func (h *UserHandler) Register(c echo.Context) (err error) {

	data := new(Userhotel)

	if err = c.Bind(data); err != nil {

		return err
	}
	//เพิ่มข้อมูล user
	stmt, err := h.DB.Prepare("INSERT INTO userhotel(email,password,firstname,lastname,birthday,tel,userpermis_id) VALUES($1,$2,$3,$4,$5,$6,2)")

	if err != nil {

		log.Println("Prepare failed:", err.Error())

	}
	//แปลง
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)
	if err != nil {

		log.Println("Error hashedPassword : ", err)

	}

	//Export data user
	_, err = stmt.Exec(data.Email, hashedPassword, data.Firstname, data.Lastname, data.Birthday, data.Tel)

	if err != nil {
		log.Println("DATABASE INSERT Error :", err.Error())
	}

	defer stmt.Close()

	return c.JSON(http.StatusOK, data)

}

func (h *UserHandler) Selectuser(c echo.Context) (err error) {

	id := c.Param("id")

	var data Userhotel

	rows, err := h.DB.Prepare("SELECT id , email,password,firstname,lastname,birthday,tel,created_by,update_by,userpermis_id FROM userhotel WHERE id = $1")
	if err != nil {
		log.Println(err)
	}

	defer rows.Close()

	var userhotels []Userhotel

	err = rows.QueryRow(id).Scan(&data.Id, &data.Email, &data.Password, &data.Firstname, &data.Lastname, &data.Birthday, &data.Tel, &data.Create_by, &data.Update_by, &data.Userpermis_id)
	if err != nil {
		log.Println("Scan failed:", err.Error())
	}

	userhotels = append(userhotels, data)

	return c.JSON(http.StatusOK, userhotels)
}

//Get room
func (h *UserHandler) getroom(c echo.Context) (err error) {

	rows, err := h.DB.Query("SELECT room.id , room.create_by_user,room.name_room,room.room_type_id,room.price ,room_type.detail FROM room AS room LEFT JOIN room_type AS room_type ON room_type.id = room.id ORDER BY room.id ASC")
	if err != nil {
		log.Println(err)
	}

	defer rows.Close()

	var CheckUse []Room

	for rows.Next() {
		var data Room
		err := rows.Scan(&data.Id, &data.Create_by_user, &data.Name_room, &data.Room_type_id, &data.Price, &data.Detail)
		if err != nil {
			log.Println("Scan failed:", err.Error())
		}
		CheckUse = append(CheckUse, data)

	}

	return c.JSON(http.StatusOK, CheckUse)
}

//total
func (h *UserHandler) total(c echo.Context) (err error) {

	var data Total

	rows, err := h.DB.Prepare("SELECT booking.id,(DATE_PART('day', create_to::date) - DATE_PART('day', create_from::date))*room.price as total FROM booking AS booking LEFT JOIN room AS room ON room.id = booking.room_id ORDER BY booking.id DESC LIMIT 1")
	if err != nil {
		log.Println(err)
	}

	defer rows.Close()

	var userhotels []Total

	err = rows.QueryRow().Scan(&data.Id, &data.Total)
	if err != nil {
		log.Println("Scan failed:", err.Error())
	}

	userhotels = append(userhotels, data)

	return c.JSON(http.StatusOK, userhotels)
}

type Newstopic struct {
	Id     int    `sql:"primary_key" json:"id" form:"id" query:"id"`
	Topic  string `json:"topic" form:"topic" query:"topic"`
	Detail string `json:"detail" form:"detail" query:"detail"`
}

//news topic
func (h *UserHandler) newstopic(c echo.Context) (err error) {

	rows, err := h.DB.Query("SELECT id , topic , detail FROM news order by id ASC ")
	if err != nil {
		log.Println(err)
	}

	defer rows.Close()

	var CheckUse []Newstopic

	for rows.Next() {
		var data Newstopic
		err := rows.Scan(&data.Id, &data.Topic, &data.Detail)
		if err != nil {
			log.Println("Scan failed:", err.Error())
		}
		CheckUse = append(CheckUse, data)
	}

	return c.JSON(http.StatusOK, CheckUse)
}

//Get user
func (h *UserHandler) user(c echo.Context) (err error) {

	token := c.Request().Header.Get("Authorization")

	decodeToken, err := ValidateToken(token)
	if err != nil {
		// err
	}

	userID := decodeToken.Id
	fmt.Println("userID ", userID)

	rows, err := h.DB.Query("SELECT id , email,firstname,lastname,birthday,tel,userpermis_id FROM userhotel WHERE id = $1", userID)
	if err != nil {
		log.Println(err)
	}

	defer rows.Close()

	var CheckUse []UserCheck

	for rows.Next() {
		var data UserCheck
		err := rows.Scan(&data.Id, &data.Email, &data.Firstname, &data.Lastname, &data.Birthday, &data.Tel, &data.Userpermis_id)
		if err != nil {
			log.Println("Scan failed:", err.Error())
		}
		CheckUse = append(CheckUse, data)
	}

	return c.JSON(http.StatusOK, CheckUse)
}

// รวม User  ทั้งหมด
func (h *UserHandler) sumuser(c echo.Context) (err error) {
	rows, err := h.DB.Query("SELECT id , email,firstname,lastname,userpermis_id FROM userhotel order by id asc")
	if err != nil {
		log.Println(err)
	}

	defer rows.Close()

	var CheckUse []UserCheck

	for rows.Next() {
		var data UserCheck
		err := rows.Scan(&data.Id, &data.Email, &data.Firstname, &data.Lastname, &data.Userpermis_id)
		if err != nil {
			log.Println("Scan failed:", err.Error())
		}
		CheckUse = append(CheckUse, data)
	}

	return c.JSON(http.StatusOK, CheckUse)
}

func (h *UserHandler) booking(c echo.Context) (err error) {

	data := new(Booking)

	if err = c.Bind(data); err != nil {

		return err
	}
	//เพิ่มข้อมูล user
	stmt, err := h.DB.Prepare("INSERT INTO booking(create_from,create_to,room_id,user_id) VALUES($1,$2,$3,$4)")

	if err != nil {

		log.Println("Prepare failed:", err.Error())

	}
	//Export data user
	_, err = stmt.Exec(data.Create_from, data.Create_to, data.Room_id, data.User_id)

	if err != nil {
		log.Println("DATABASE INSERT Error :", err.Error())
	}

	defer stmt.Close()

	return c.JSON(http.StatusOK, data)
}

//gdituser
func (h *UserHandler) edituser(c echo.Context) (err error) {

	data := new(Userhotel)

	if err := c.Bind(data); err != nil {
		return err
	}

	id := c.Param("id")

	stmt, err := h.DB.Prepare("UPDATE userhotel SET firstname=$1, lastname=$2,tel=$3 WHERE id= $4 ")

	if err != nil {
		return err
	}

	_, err = stmt.Exec(data.Firstname, data.Lastname, data.Tel, id)

	if err != nil {
		return err
	}

	defer stmt.Close()

	return c.JSON(http.StatusOK, data)
}
func main() {

	fmt.Println("Welcome to the server")

	port := os.Getenv("PORT")

	h := UserHandler{}

	h.Initialize()

	e := echo.New()

	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: "method=${method}, uri=${uri}, status=${status}\n",
	}))

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"http://localhost:3000", "http://127.0.0.1:3000"},
		AllowMethods: []string{http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete},
	}))

	e.GET("/sumuser", h.sumuser) //func รวมผู้ใช้งานทั้งหมด

	e.GET("/user", h.user) //func ค้นหาผู้ใช้งานผ่าน Token

	e.GET("/Selectuser/:id", h.Selectuser) //func ค้นหาผู้ใช้งาน

	e.GET("/total", h.total) //func รวมราคา

	e.GET("/selectroom", h.getroom) //func ค้นหาห้อง

	e.GET("/new", h.newstopic) //func ข่าวประชาสัมพันธ์

	e.POST("/login", h.login) //func เข้าสู่ระบบ

	e.POST("/Register", h.Register) //func สมัครสมาชิก

	e.POST("/booking", h.booking) //func จอง

	e.PUT("/edituser/:id", h.edituser) //func แก้ไขผู้ใช้งาน

	e.Start(":" + port)

}

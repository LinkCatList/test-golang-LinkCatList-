package main

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
	"unicode"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

const signingKey = "14jf34gnv3n04j3v228"

type Server struct {
	address string
	logger  *slog.Logger
	db      *sqlx.DB
}
type Country struct {
	Name   string `json:"name" db:"name"`
	Alpha2 string `json:"alpha2" db:"alpha2"`
	Alpha3 string `json:"alpha3" db:"alpha3"`
	Region string `json:"region" db:"region"`
}
type User struct {
	Login       string `json:"login"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	CountryCode string `json:"countryCode"`
	IsPublic    string `json:"isPublic"`
	Phone       string `json:"phone,omitempty"`
	Image       string `json:"image,omitempty"`
}
type ResponseUser struct {
	Login       string `json:"login"`
	Email       string `json:"email"`
	CountryCode string `json:"countryCode"`
	IsPublic    string `json:"isPublic"`
	Phone       string `json:"phone,omitempty"`
	Image       string `json:"image,omitempty"`
}
type AuthUser struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}
type TokenClaims struct {
	jwt.StandardClaims
	Login string `json:"login"`
}
type TokenResponse struct {
	Token string `json:"token"`
}
type TokenLogin struct {
	Token string `json:"token"`
	Login string `json:"login"`
	// IsValid bool   `json:"isValid"`
}
type RequestChangePass struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}
type FiendRequest struct {
	Login string `json:"login"`
}
type Friends struct {
	Login2    string `json:"login" db:"login2"`
	CreatedAt string `json:"addedAt"`
}
type Pagination struct {
	Limit  string `json:"paginationLimit"`
	Offset string `json:"paginationOffset"`
}
type Posts struct {
	Content string   `json:"content"`
	Tags    []string `json:"tags"`
}
type PostResponse struct {
	Id            string   `json:"id"`
	Content       string   `json:"content"`
	Author        string   `json:"author"`
	Tags          []string `json:"tags"`
	CreatedAt     string   `json:"createdAt"`
	LikesCount    int      `json:"likesCount"`
	DislikesCount int      `json:"dislikesCount"`
}

func NewServer(address string, logger *slog.Logger, db *sqlx.DB) *Server {
	return &Server{
		address: address,
		logger:  logger,
		db:      db,
	}
}

func (s *Server) Start() error {
	// таблица пользователей
	query := "create table if not exists users5 (id serial, login text, password text, email text, countryCode text, isPublic text, phone text, image text);"
	_, err4 := s.db.Exec(query)
	if err4 != nil {
		fmt.Println(err4)
	}
	// таблица действительных на текущий момент токенов
	query = "create table if not exists tokens (token text, login text);"
	_, err4 = s.db.Exec(query)
	if err4 != nil {
		fmt.Println(err4)
	}
	// таблица связей друзей (не половых)
	query = "create table if not exists friends3(login1 text, login2 text, createdAt timestamptz);"
	_, err4 = s.db.Exec(query)
	if err4 != nil {
		fmt.Println(err4)
	}

	query = "create table if not exists posts2(id text, login text, content text, tags text[], createdAt text, likes int, dislikes int);"
	_, err4 = s.db.Exec(query)
	if err4 != nil {
		fmt.Println(err4)
	}
	// таблица лайков/дизлайков, 0 - дизлайк, 1 - лайк
	query = "create table if not exists reactions(login text, postId text, reaction boolean);"
	_, err4 = s.db.Exec(query)
	if err4 != nil {
		fmt.Println(err4)
	}

	router := mux.NewRouter()

	router.HandleFunc("/api/ping", s.handlePing).Methods("GET")
	router.HandleFunc("/api/countries", s.handleGetAllCountries).Methods("GET")
	router.HandleFunc("/api/countries/{alpha2}", s.handleGetCountryByAlpha2).Methods("GET")
	router.HandleFunc("/api/auth/register", s.handleRegisterUser).Methods("POST")
	router.HandleFunc("/api/auth/sign-in", s.handleSignIn).Methods("POST")
	router.HandleFunc("/api/me/profile", s.GetProfile)
	router.HandleFunc("/api/profiles/{login}", s.handleGetUserByLogin).Methods("GET")
	router.HandleFunc("/api/me/updatePassword", s.handleUpdPassword).Methods("POST")
	router.HandleFunc("/api/friends/add", s.handleFriendAdd).Methods("POST")
	router.HandleFunc("/api/friends/remove", s.handleRemoveFriend).Methods("POST")
	router.HandleFunc("/api/friends", s.handleGetFriends).Methods("GET")
	router.HandleFunc("/api/posts/new", s.handleNewPost).Methods("POST")
	router.HandleFunc("/api/posts/{postId}", s.handleGetPost).Methods("GET")
	router.HandleFunc("/api/posts/feed/my", s.handleGetMyFeed).Methods("GET")
	router.HandleFunc("/api/posts/feed/{login}", s.handleGetUserFeed).Methods("GET")
	router.HandleFunc("/api/posts/{postId}/like", s.handleLikePost).Methods("POST")
	router.HandleFunc("/api/posts/{postId}/dislike", s.handleDislikePost).Methods("POST")

	s.logger.Info("server has been started", "address", s.address)

	err := http.ListenAndServe(s.address, router)
	if err != http.ErrServerClosed {
		return err
	}

	return nil
}
func (s *Server) handleGetAllCountries(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	//region := query.Get("region")
	var region []string
	for _, values := range query {
		for _, val := range values {
			region = append(region, val)
		}
	}
	for _, val := range region {
		if val != "Europe" && val != "Africa" && val != "Americas" && val != "Oceania" && val != "Asia" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"reason": "invalid data"}`))
			return
		}
	}
	//fmt.Println(region)
	if len(region) == 0 {
		var countries_list []Country
		q := "select name, alpha2, alpha3, region from countries"
		rows, err := s.db.Query(q)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"reason": "region not found"}`))
			return

		}
		for rows.Next() {
			var name, alpha2, alpha3, region string
			rows.Scan(&name, &alpha2, &alpha3, &region)
			countries_list = append(countries_list, Country{Name: name, Alpha2: alpha2, Alpha3: alpha3, Region: region})
		}
		json.NewEncoder(w).Encode(countries_list)
	} else {
		var countries_list []Country
		q := "select name, alpha2, alpha3, region from countries where region in("
		for i, value := range region {
			if i > 0 {
				q += ", "
			}
			q += "'" + value + "'"
		}
		q += ");"
		//fmt.Println(q)
		rows, err := s.db.Query(q)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"reason": "not found"}`))
			return
		}
		for rows.Next() {
			var s Country
			rows.Scan(&s.Name, &s.Alpha2, &s.Alpha3, &s.Region)
			countries_list = append(countries_list, s)
		}
		sort.SliceStable(countries_list, func(i, j int) bool {
			return countries_list[i].Alpha2 < countries_list[j].Alpha2
		})
		json.NewEncoder(w).Encode(countries_list)
	}
}
func (s *Server) handleGetCountryByAlpha2(w http.ResponseWriter, r *http.Request) {
	alpha2, ok := mux.Vars(r)["alpha2"]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	var country Country
	err := s.db.QueryRow("select name, alpha2, alpha3, region from countries where alpha2=$1", alpha2).Scan(&country.Name, &country.Alpha2, &country.Alpha3, &country.Region)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"reason": "country not found"}`))
		return
	}
	json.NewEncoder(w).Encode(country)
}
func (s *Server) handleGetAll(w http.ResponseWriter, r *http.Request) {
	var country []string
	rows, err := s.db.Query("select name from countries")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	for rows.Next() {
		var s string
		rows.Scan(&s)
		country = append(country, s)
	}
	json.NewEncoder(w).Encode(country)
}
func (s *Server) handlePing(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("ok"))
}
func ValidateLogin(name string) bool {
	return (len(name) <= 30 && len(name) >= 1)
}
func ValidateEmail(email string) bool {
	return (len(email) <= 50 && len(email) >= 1)
}
func ValidatePassword(password string) bool {
	if len(password) < 6 {
		return false
	}
	wasNum, wasLow, wasUp := false, false, false
	for _, val := range password {
		if unicode.IsLower(val) {
			wasLow = true
		}
		if unicode.IsDigit(val) {
			wasNum = true
		}
		if unicode.IsUpper(val) {
			wasUp = true
		}
	}
	return wasNum && wasLow && wasUp
}
func ValidatePhone(phone string) bool {
	cnt := 0
	for _, val := range phone {
		if !unicode.IsDigit(val) {
			cnt++
		}
	}
	return (cnt <= 1 && phone[0] == '+' && len(phone) >= 1)
}
func ValidateImgLink(imglink string) bool {
	return len(imglink) == 0
}
func (s *Server) ValidateToken(Token string) bool {
	var exists bool
	query := "select exists(select 1 from tokens where token=$1)"
	err228 := s.db.QueryRow(query, Token).Scan(&exists)
	if err228 != nil {
		fmt.Println("error while check")
		return false
	}
	return exists
}
func (s *Server) handleRegisterUser(w http.ResponseWriter, r *http.Request) {
	var user User
	query1 := r.URL.Query()
	user.Login = query1.Get("login")
	user.Email = query1.Get("email")
	user.Password = query1.Get("password")
	user.CountryCode = query1.Get("countryCode")
	user.IsPublic = query1.Get("isPublic")
	user.Phone = query1.Get("phone")

	// fmt.Println(user.Phone)
	fmt.Println(ValidateEmail(user.Email), ValidateLogin(user.Login), ValidateImgLink(user.Image), ValidatePassword(user.Password), ValidatePhone(user.Phone))
	if !ValidateEmail(user.Email) || !ValidateLogin(user.Login) || !ValidateImgLink(user.Image) || !ValidatePassword(user.Password) || !ValidatePhone(user.Phone) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}

	hash := sha512.Sum512([]byte(user.Login + user.Password))
	hashedPassword := hex.EncodeToString(hash[:])

	var exists bool

	query := "select exists(select 1 from users5 where login=$1)"
	err228 := s.db.QueryRow(query, user.Login).Scan(&exists)
	if err228 != nil {
		fmt.Println("error while check")
	}
	if exists {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"reason": "exists"}`))
		return
	}
	query = "select exists(select 1 from users5 where email=$1)"
	err228 = s.db.QueryRow(query, user.Email).Scan(&exists)
	if err228 != nil {
		fmt.Println("error while check")
	}
	if exists {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"reason": "exists"}`))
		return
	}
	query = "select exists(select 1 from users5 where phone=$1)"
	err228 = s.db.QueryRow(query, user.Phone).Scan(&exists)
	if err228 != nil {
		fmt.Println("error while check")
	}
	if exists {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"reason": "exists"}`))
		return
	}
	// -------------------------------------------
	file, header, err := r.FormFile("image")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	defer file.Close()

	hash = sha512.Sum512([]byte(header.Filename + user.Password))
	hashedPath := hex.EncodeToString(hash[:])

	newFile, err := os.Create("./images/" + hashedPath + ".png")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	defer newFile.Close()
	_, err = io.Copy(newFile, file)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}

	user.Image = "./images/" + hashedPath + ".png"
	// -------------------------------------------------
	fmt.Println(user.Login)
	query = "insert into users5 values(default, $1, $2, $3, $4, $5, $6, $7);"
	_, err2 := s.db.Exec(query, user.Login, hashedPassword, user.Email, user.CountryCode, user.IsPublic, user.Phone, user.Image)
	if err2 != nil {
		fmt.Println("error while insert into db", err2)
	}
	ans := ResponseUser{
		Login:       user.Login,
		Email:       user.Email,
		CountryCode: user.CountryCode,
		IsPublic:    user.IsPublic,
		Phone:       user.Phone,
		Image:       user.Image,
	}
	profileJson, _ := json.Marshal(ans)
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(fmt.Sprintf(`{"profile": %s}`, profileJson)))
}

func (s *Server) generateToken(login string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &TokenClaims{
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(12 * time.Hour).Unix(), // токен валиден в течение 12 часов
			IssuedAt:  time.Now().Unix(),
		},
		login,
	})
	ResToken, err := token.SignedString([]byte(signingKey))
	query := "insert into tokens (token, login) values($1, $2)"
	_, err1 := s.db.Exec(query, ResToken, login)
	if err1 != nil {
		fmt.Println("error while insert into db")
		return "", err1
	}
	return ResToken, err
}
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	var user AuthUser
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error while reading json"}`))
		return
	}

	var exists bool
	query := "select exists(select 1 from users5 where login=$1)"
	err228 := s.db.QueryRow(query, user.Login).Scan(&exists)
	if err228 != nil {
		fmt.Println("error while check")
	}
	if !exists {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "user doesnt exists"}`))
		return
	}
	var InputPassword string
	err3 := s.db.QueryRow("select password from users5 where login=$1", user.Login).Scan(&InputPassword)
	if err3 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error while get user from db"}`))
		return
	}
	hash := sha512.Sum512([]byte(user.Login + user.Password))
	hashedPassword := hex.EncodeToString(hash[:])

	// fmt.Println("hashed", hashedPassword)
	// fmt.Println("input ", InputPassword)
	if hashedPassword != InputPassword {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "incorrect password"}`))
		return
	}
	token, err1 := s.generateToken(user.Login)
	if err1 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error while create token"}`))
	}
	Rtoken := TokenResponse{
		Token: token,
	}
	TokenJson, _ := json.Marshal(Rtoken)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(TokenJson))
}
func (s *Server) GetProfile(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "authorization token is required"}`))
		return
	}
	token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
	if err != nil || !token.Valid || !s.ValidateToken(tokenString[7:]) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "invalid token"}`))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "invalid token claims}`))
		return
	}
	login, ok := claims["login"].(string)
	fmt.Println(login)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "invalid token claims"}`))
		return
	}
	switch r.Method {
	case http.MethodGet:
		var users []ResponseUser
		// user.Login = login
		q := "select login, email, countryCode, isPublic, phone, image from users5 where login=$1"
		row, err2 := s.db.Query(q, login)
		if err2 != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"reason": "error"}`))
			return
		}
		for row.Next() {
			var user ResponseUser
			row.Scan(&user.Login, &user.Email, &user.CountryCode, &user.IsPublic, &user.Phone, &user.Image)
			users = append(users, user)
		}
		fmt.Println(users[0])
		TokenJson, _ := json.Marshal(users[0])
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(TokenJson))
	case http.MethodPatch:
		var user User
		query1 := r.URL.Query()
		user.CountryCode = query1.Get("countryCode")
		user.IsPublic = query1.Get("isPublic")
		user.Phone = query1.Get("phone")
		rphone := []rune(user.Phone)
		if len(rphone) > 0 && rphone[0] == ' ' {
			rphone[0] = '+'
		}
		user.Phone = string(rphone)
		file, header, err := r.FormFile("image")
		if err != nil && file != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"reason": "error"}`))
			return
		}
		if file == nil {
			user.Image = ""
		}
		if file != nil {
			defer file.Close()
			hash := sha512.Sum512([]byte(header.Filename + user.Password))
			hashedPath := hex.EncodeToString(hash[:])
			newFile, err := os.Create("./images/" + hashedPath + ".png")
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
			defer newFile.Close()
			_, err = io.Copy(newFile, file)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
			user.Image = "./images/" + hashedPath + ".png"
		}
		if user.CountryCode != "" {
			var exists bool
			query := "select exists(select 1 from countries where alpha2=$1)"
			err228 := s.db.QueryRow(query, user.CountryCode).Scan(&exists)
			if err228 != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
			if !exists {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
			q := "update users5 set countryCode=$1 where login=$2;"
			_, err2 := s.db.Exec(q, user.CountryCode, login)
			if err2 != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
		}
		fmt.Println(user.Image)
		if user.Image != "" {
			q := "update users5 set image=$1 where login=$2;"
			_, err2 := s.db.Exec(q, user.Image, login)
			if err2 != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
		}
		if user.Phone != "" {
			if !ValidatePhone(user.Phone) {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
			var exists bool
			query := "select exists(select 1 from users5 where phone=$1 and login != $2)"
			err228 := s.db.QueryRow(query, user.Phone, login).Scan(&exists)
			if err228 != nil {
				fmt.Println(1)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
			if exists {
				w.WriteHeader(http.StatusConflict)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
			q := "update users5 set phone=$1 where login=$2;"
			_, err2 := s.db.Exec(q, user.Phone, login)
			if err2 != nil {
				fmt.Println(err2)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
		}
		if user.IsPublic != "" {
			q := "update users5 set isPublic=$1 where login=$2;"
			_, err2 := s.db.Exec(q, user.IsPublic, login)
			if err2 != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
		}
		var users []ResponseUser
		q := "select login, email, countryCode, isPublic, phone, image from users5 where login=$1"
		row, err2 := s.db.Query(q, login)
		if err2 != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"reason": "error"}`))
			return
		}
		for row.Next() {
			var user ResponseUser
			row.Scan(&user.Login, &user.Email, &user.CountryCode, &user.IsPublic, &user.Phone, &user.Image)
			users = append(users, user)
		}
		fmt.Println(users[0])
		TokenJson, _ := json.Marshal(users[0])
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(TokenJson))
	}
}
func (s *Server) handleGetUserByLogin(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
	if err != nil || !token.Valid || !s.ValidateToken(tokenString[7:]) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	login, ok := claims["login"].(string)
	fmt.Println(login)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	loginInput, ok := mux.Vars(r)["login"]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	var user []ResponseUser
	q := "select login, email, countryCode, isPublic, phone, image from users5 where login=$1"
	row, err1 := s.db.Query(q, loginInput)
	if err1 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	for row.Next() {
		var CurUser ResponseUser
		row.Scan(&CurUser.Login, &CurUser.Email, &CurUser.CountryCode, &CurUser.IsPublic, &CurUser.Phone, &CurUser.Image)
		user = append(user, CurUser)
	}
	fmt.Println(login, loginInput)
	if login == loginInput {
		json.NewEncoder(w).Encode(user[0])
		return
	} else if user[0].IsPublic == "" {
		json.NewEncoder(w).Encode(user[0])
		return
	}
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"reason": "error"}`))
}
func (s *Server) handleUpdPassword(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
	if err != nil || !token.Valid || !s.ValidateToken(tokenString[7:]) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	login, ok := claims["login"].(string)
	if !ok {
		fmt.Println(1)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	query := "delete from tokens where login=$1;"
	_, err1 := s.db.Exec(query, login)
	if err1 != nil {
		// fmt.Println(2)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	_, err2 := s.generateToken(login)
	if err2 != nil {
		// fmt.Println(3)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	query = "select password from users5 where login=$1"
	var HashedPasswordFromDb string
	err3 := s.db.QueryRow(query, login).Scan(&HashedPasswordFromDb)
	if err3 != nil {
		// fmt.Println(4)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	var RCP RequestChangePass
	err4 := json.NewDecoder(r.Body).Decode(&RCP)
	if err4 != nil {
		// fmt.Println(5)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	OldPassword := RCP.OldPassword
	NewPassword := RCP.NewPassword
	// fmt.Println(OldPassword, NewPassword)

	hash := sha512.Sum512([]byte(login + OldPassword))
	hashedOldPassword := hex.EncodeToString(hash[:])
	// fmt.Println(HashedPasswordFromDb, hashedOldPassword)
	if HashedPasswordFromDb != hashedOldPassword {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if !ValidatePassword(NewPassword) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	hash = sha512.Sum512([]byte(login + NewPassword))
	hashedNewPassword := hex.EncodeToString(hash[:])
	query = "update users5 set password=$1 where login=$2"
	_, err5 := s.db.Exec(query, hashedNewPassword, login)
	if err5 != nil {
		// fmt.Println(7)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "ok"}`))
}
func (s *Server) handleFriendAdd(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
	if err != nil || !token.Valid || !s.ValidateToken(tokenString[7:]) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	login, ok := claims["login"].(string)
	var FriendLogin FiendRequest
	err = json.NewDecoder(r.Body).Decode(&FriendLogin)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}

	var exists bool
	query := "select exists(select 1 from users5 where login=$1)"
	err228 := s.db.QueryRow(query, FriendLogin.Login).Scan(&exists)
	if err228 != nil {
		fmt.Println("error while check", err228)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	fmt.Println(FriendLogin.Login, login)
	query = "select exists(select 1 from friends3 where login1=$1 and login2=$2)"
	err228 = s.db.QueryRow(query, login, FriendLogin.Login).Scan(&exists)
	if err228 != nil {
		fmt.Println("error while check", err228)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if exists {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
		return
	}
	query = "insert into friends3 values ($1, $2, $3);"
	currentTime := time.Now()
	str, _ := currentTime.MarshalJSON()
	rfc3339Time := string(str)
	fmt.Println(currentTime, rfc3339Time)
	_, err3 := s.db.Exec(query, login, FriendLogin.Login, rfc3339Time)
	if err3 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "ok"}`))
}
func (s *Server) handleGetFriends(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
	if err != nil || !token.Valid || !s.ValidateToken(tokenString[7:]) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	login, ok := claims["login"].(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	q := r.URL.Query()
	var pagination Pagination
	pagination.Limit = q.Get("paginationLimit")
	pagination.Offset = q.Get("paginationOffset")
	if pagination.Offset == "" {
		pagination.Offset = "0"
	}
	if pagination.Limit == "" {
		pagination.Limit = "5"
	}
	num, err := strconv.Atoi(pagination.Offset)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if num < 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	num, err = strconv.Atoi(pagination.Limit)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if num < 0 || num > 50 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	// fmt.Println(pagination)
	query := "select login2, createdAt from friends3 where login1=$1 order by createdAt desc limit $2 offset $3"
	row, err := s.db.Query(query, login, pagination.Limit, pagination.Offset)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	var friends []Friends
	for row.Next() {
		var friend Friends
		row.Scan(&friend.Login2, &friend.CreatedAt)
		sr := []rune(friend.CreatedAt)
		sr[len(sr)-6] = 'Z'
		friend.CreatedAt = string(sr)
		friends = append(friends, friend)
	}
	json.NewEncoder(w).Encode(friends)
}
func (s *Server) handleRemoveFriend(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
	if err != nil || !token.Valid || !s.ValidateToken(tokenString[7:]) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	login, ok := claims["login"].(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	var FriendLogin FiendRequest
	err = json.NewDecoder(r.Body).Decode(&FriendLogin)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	var exists bool
	fmt.Println(FriendLogin.Login, login)
	query := "select exists(select 1 from friends3 where login1=$1 and login2=$2)"
	err228 := s.db.QueryRow(query, login, FriendLogin.Login).Scan(&exists)
	if err228 != nil {
		fmt.Println("error while check", err228)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if !exists {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
		return
	}
	query = "delete from friends3 where login1=$1 and login2=$2;"
	_, err3 := s.db.Exec(query, login, FriendLogin.Login)
	if err3 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "ok"}`))
}
func (s *Server) handleNewPost(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
	if err != nil || !token.Valid || !s.ValidateToken(tokenString[7:]) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	login, ok := claims["login"].(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	var Post Posts
	err = json.NewDecoder(r.Body).Decode(&Post)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}

	currentTime := time.Now()
	str, _ := currentTime.MarshalJSON()
	rs := []rune(string(str))
	rs[len(str)-7] = 'Z'
	str = []byte(string(rs))
	rfc3339Time := string(str)[1 : len(str)-1]

	hash := sha512.Sum512([]byte(string(rs) + Post.Content))
	hashedId := hex.EncodeToString(hash[:])

	hashedId = hashedId[:90]
	query := "insert into posts2 values ($1, $2, $3, $4, $5, 0, 0);"
	_, err = s.db.Exec(query, hashedId, login, Post.Content, pq.Array(Post.Tags), rfc3339Time)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}

	fmt.Println(rfc3339Time)
	RPost := PostResponse{
		Id:            hashedId,
		Content:       Post.Content,
		Author:        login,
		Tags:          Post.Tags,
		CreatedAt:     rfc3339Time,
		LikesCount:    0,
		DislikesCount: 0,
	}
	json.NewEncoder(w).Encode(RPost)
}
func (s *Server) handleGetPost(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
	if err != nil || !token.Valid || !s.ValidateToken(tokenString[7:]) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	login, ok := claims["login"].(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	PostId, ok := mux.Vars(r)["postId"]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	var exists bool
	query := "select exists(select 1 from posts2 where id=$1)"
	err228 := s.db.QueryRow(query, PostId).Scan(&exists)
	if err228 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
	}
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"reason": "not found"}`))
		return
	}
	query = "select * from posts2 where id=$1"
	rows, err := s.db.Query(query, PostId)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	var posts []PostResponse
	for rows.Next() {
		var post PostResponse
		rows.Scan(&post.Id, &post.Author, &post.Content, pq.Array(&post.Tags), &post.CreatedAt, &post.LikesCount, &post.DislikesCount)
		posts = append(posts, post)
	}

	if posts[0].Author == login {
		json.NewEncoder(w).Encode(posts[0])
		return
	}

	query = "select exists(select 1 from friends3 where login1=$1 and login2=$2)"
	err228 = s.db.QueryRow(query, posts[0].Author, login).Scan(&exists)
	if err228 != nil {
		fmt.Println(err228)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error whiel check"}`))
		return
	}
	if exists {
		json.NewEncoder(w).Encode(posts[0])
		return
	}
	query = "select isPublic from users5 where login=$1"
	var is_public bool
	err = s.db.QueryRow(query, posts[0].Author).Scan(&is_public)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error whiel check"}`))
		return
	}
	if !is_public {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"reason": "not found"}`))
		return
	}
	json.NewEncoder(w).Encode(posts[0])
}
func (s *Server) handleGetMyFeed(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
	if err != nil || !token.Valid || !s.ValidateToken(tokenString[7:]) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	login, ok := claims["login"].(string)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	q := r.URL.Query()
	var pagination Pagination
	pagination.Limit = q.Get("paginationLimit")
	pagination.Offset = q.Get("paginationOffset")
	if pagination.Offset == "" {
		pagination.Offset = "0"
	}
	if pagination.Limit == "" {
		pagination.Limit = "5"
	}
	num, err := strconv.Atoi(pagination.Offset)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if num < 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	num, err = strconv.Atoi(pagination.Limit)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if num < 0 || num > 50 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}

	query := "select * from posts2 where login=$1 order by createdAt desc limit $2 offset $3"
	rows, err := s.db.Query(query, login, pagination.Limit, pagination.Offset)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	var posts []PostResponse
	for rows.Next() {
		var post PostResponse
		rows.Scan(&post.Id, &post.Author, &post.Content, pq.Array(&post.Tags), &post.CreatedAt, &post.LikesCount, &post.DislikesCount)
		posts = append(posts, post)
	}
	json.NewEncoder(w).Encode(posts)
}
func (s *Server) handleGetUserFeed(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
	if err != nil || !token.Valid || !s.ValidateToken(tokenString[7:]) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	login, ok := claims["login"].(string)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	q := r.URL.Query()
	var pagination Pagination
	pagination.Limit = q.Get("paginationLimit")
	pagination.Offset = q.Get("paginationOffset")
	if pagination.Offset == "" {
		pagination.Offset = "0"
	}
	if pagination.Limit == "" {
		pagination.Limit = "5"
	}
	num, err := strconv.Atoi(pagination.Offset)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if num < 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	num, err = strconv.Atoi(pagination.Limit)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if num < 0 || num > 50 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	var user FiendRequest
	user.Login, ok = mux.Vars(r)["login"]
	if !ok {
		fmt.Println(ok)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	fmt.Println(user.Login)
	var exists bool
	query := "select exists(select 1 from users5 where login=$1)"
	err228 := s.db.QueryRow(query, user.Login).Scan(&exists)
	if err228 != nil {
		fmt.Println(err228)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error whiel check"}`))
		return
	}
	if !exists {
		fmt.Println("not found")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	query = "select * from posts2 where login=$1 order by createdAt desc limit $2 offset $3"
	rows, err := s.db.Query(query, login, pagination.Limit, pagination.Offset)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	var posts []PostResponse
	for rows.Next() {
		var post PostResponse
		rows.Scan(&post.Id, &post.Author, &post.Content, pq.Array(&post.Tags), &post.CreatedAt, &post.LikesCount, &post.DislikesCount)
		posts = append(posts, post)
	}
	fmt.Println(user.Login, login)
	query = "select exists(select 1 from friends3 where login1=$1 and login2=$2)"
	err228 = s.db.QueryRow(query, user.Login, login).Scan(&exists)
	if err228 != nil {
		fmt.Println(err228)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if exists {
		json.NewEncoder(w).Encode(posts)
		return
	}
	query = "select isPublic from users5 where login=$1"
	var is_public bool
	err228 = s.db.QueryRow(query, user.Login).Scan(&is_public)
	if err228 != nil {
		fmt.Println("228", err228)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if is_public {
		json.NewEncoder(w).Encode(posts)
		return
	}
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte(`{"reason": "error"}`))
}
func (s *Server) handleLikePost(w http.ResponseWriter, r *http.Request) {
	PostId, ok := mux.Vars(r)["postId"]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
	if err != nil || !token.Valid || !s.ValidateToken(tokenString[7:]) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	login, ok := claims["login"].(string)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	query := "select login from posts2 where id=$1"
	var UserLogin string
	err = s.db.QueryRow(query, PostId).Scan(&UserLogin)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	sperm := false // может ли чувак поставить лайк
	var exists bool
	query = "select exists(select 1 from friends3 where login1=$1 and login2=$2)"
	err228 := s.db.QueryRow(query, UserLogin, login).Scan(&exists)
	if err228 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if exists {
		sperm = true
	}
	query = "select isPublic from users5 where login=$1"
	var IsPublic bool
	err = s.db.QueryRow(query, UserLogin).Scan(&IsPublic)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if IsPublic {
		sperm = true
	}
	query = "select exists(select 1 from posts2 where id=$1)"
	err228 = s.db.QueryRow(query, PostId).Scan(&exists)
	if err228 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if !sperm {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	query = "select exists(select 1 from reactions where login=$1)"
	err228 = s.db.QueryRow(query, login).Scan(&exists)
	if err228 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	fmt.Println(exists)
	if !exists {
		query = "insert into reactions (login, postId, reaction) values ($1, $2, true);"
		_, err = s.db.Exec(query, login, PostId)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"reason": "error"}`))
			return
		}
		query = "select likes, dislikes from posts2 where id=$1"
		rows, err := s.db.Query(query, PostId)
		if err != nil {
			fmt.Println(6)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"reason": "error"}`))
			return
		}
		countLikes := 0
		countDislikes := 0
		for rows.Next() {
			rows.Scan(&countLikes, &countDislikes)
		}
		query = "update posts2 set likes=$1 where id=$2"
		_, err = s.db.Exec(query, countLikes+1, PostId)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"reason": "error"}`))
			return
		}
	} else {
		query = "select reaction from reactions where login=$1 and postId=$2"
		var reaction bool
		err = s.db.QueryRow(query, login, PostId).Scan(&reaction)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"reason": "error"}`))
			return
		}
		if !reaction {
			query = "update reactions set reaction=true where login=$1 and postId=$2"
			_, err = s.db.Exec(query, login, PostId)
			if err != nil {
				fmt.Println(5)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
			query = "select likes, dislikes from posts2 where id=$1"
			rows, err := s.db.Query(query, PostId)
			if err != nil {
				fmt.Println(6)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
			countLikes := 0
			countDislikes := 0
			for rows.Next() {
				rows.Scan(&countLikes, &countDislikes)
			}
			query = "update posts2 set likes=$1, dislikes=$2 where id=$3"
			fmt.Println("ok")
			_, err = s.db.Exec(query, countLikes+1, countDislikes-1, PostId)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
		}
	}
}
func (s *Server) handleDislikePost(w http.ResponseWriter, r *http.Request) {
	PostId, ok := mux.Vars(r)["postId"]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}

	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	token, err := jwt.Parse(tokenString[7:], func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
	if err != nil || !token.Valid || !s.ValidateToken(tokenString[7:]) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	login, ok := claims["login"].(string)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}

	query := "select login from posts2 where id=$1"
	var UserLogin string
	err = s.db.QueryRow(query, PostId).Scan(&UserLogin)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	sperm := false // может ли чувак поставить дизлайк
	var exists bool
	query = "select exists(select 1 from friends3 where login1=$1 and login2=$2)"
	err228 := s.db.QueryRow(query, UserLogin, login).Scan(&exists)
	if err228 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if exists {
		sperm = true
	}
	query = "select isPublic from users5 where login=$1"
	var IsPublic bool
	err = s.db.QueryRow(query, UserLogin).Scan(&IsPublic)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if IsPublic {
		sperm = true
	}
	query = "select exists(select 1 from posts2 where id=$1)"
	err228 = s.db.QueryRow(query, PostId).Scan(&exists)
	if err228 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	if !sperm {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	query = "select exists(select 1 from reactions where login=$1)"
	err228 = s.db.QueryRow(query, login).Scan(&exists)
	if err228 != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"reason": "error"}`))
		return
	}
	fmt.Println(exists)
	if !exists {
		query = "insert into reactions (login, postId, reaction) values ($1, $2, true);"
		_, err = s.db.Exec(query, login, PostId)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"reason": "error"}`))
			return
		}
		query = "select likes, dislikes from posts2 where id=$1"
		rows, err := s.db.Query(query, PostId)
		if err != nil {
			fmt.Println(6)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"reason": "error"}`))
			return
		}
		countLikes := 0
		countDislikes := 0
		for rows.Next() {
			rows.Scan(&countLikes, &countDislikes)
		}
		query = "update posts2 set dislikes=$1 where id=$2"
		_, err = s.db.Exec(query, countDislikes+1, PostId)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"reason": "error"}`))
			return
		}
	} else {
		query = "select reaction from reactions where login=$1 and postId=$2"
		var reaction bool
		err = s.db.QueryRow(query, login, PostId).Scan(&reaction)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"reason": "error"}`))
			return
		}
		fmt.Println("reaction=", reaction)
		if reaction {
			query = "update reactions set reaction=false where login=$1 and postId=$2"
			_, err = s.db.Exec(query, login, PostId)
			if err != nil {
				fmt.Println(5)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
			query = "select likes, dislikes from posts2 where id=$1"
			rows, err := s.db.Query(query, PostId)
			if err != nil {
				fmt.Println(6)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
			countLikes := 0
			countDislikes := 0
			for rows.Next() {
				rows.Scan(&countLikes, &countDislikes)
			}
			query = "update posts2 set likes=$1, dislikes=$2 where id=$3"
			_, err = s.db.Exec(query, countLikes-1, countDislikes+1, PostId)
			if err != nil {
				fmt.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"reason": "error"}`))
				return
			}
		}
	}
}

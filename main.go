package main

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"golang.org/x/crypto/bcrypt"
)

var (
	db        *bun.DB
	secretKey = []byte("super-secret-key")
)

var (
	sqldb *sql.DB
)

type User struct {
	bun.BaseModel `bun:"table:demo_users"`

	ID       int64  `bun:",pk,autoincrement"`
	UserName string `bun:",unique,notnull"`
	Password string `bun:",notnull"`
}

func initDB() {
	dsn := "postgres://postgres:anirudh10@localhost:5432/postgres?sslmode=disable"

	sqldb = sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
	db = bun.NewDB(sqldb, pgdialect.New())

	if _, err := db.NewCreateTable().Model((*User)(nil)).IfNotExists().Exec(context.TODO()); err != nil {
		log.Fatalf("create table: %v", err)
	}
}

func main() {
	initDB()

	r := gin.Default()

	r.POST("/register", registerHandler)
	r.POST("/login", loginHandler)

	authorized := r.Group("/")
	authorized.Use(AuthMiddleware())
	{
		authorized.GET("/profile", profileHandler)
	}

	r.Run(":8080")
}

func registerHandler(c *gin.Context) {
	var input struct {
		UserName string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Hashing failed"})
		return
	}

	user := &User{UserName: input.UserName, Password: string(hashed)}
	_, err = db.NewInsert().Model(user).Exec(c.Request.Context())
	if err != nil {
		log.Println(err)
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered"})
}

func loginHandler(c *gin.Context) {
	var input struct {
		UserName string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	user := new(User)
	err := db.NewSelect().Model(user).Where("user_name = ?", input.UserName).Scan(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Create JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":   user.ID,
		"user_name": user.UserName,
		"exp":       time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Token creation failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func profileHandler(c *gin.Context) {
	user, _ := c.Get("user")
	c.JSON(http.StatusOK, gin.H{"profile": user})
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid token"})
			return
		}

		tokenString := authHeader[7:]
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return secretKey, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			log.Println("Token parsing error:", err)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			c.Set("user", claims)
			c.Next()
		} else {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token claims invalid"})
			return
		}
	}
}

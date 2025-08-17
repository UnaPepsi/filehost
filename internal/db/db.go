package db

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"filehost/internal/responses"
	"fmt"
	"io"
	"log"
	"math/big"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
)

var pgURL string
var ctx context.Context
var totpSecretRegister string
var passwordRegisterCode string
func Initialize() (err error) {
	ctx = context.Background()
	var exists bool
	if pgURL,exists = os.LookupEnv("PG_URL"); !exists {
		log.Fatal("Missing env variable \"PG_URL\"")
	}
	totpSecretRegister, exists = os.LookupEnv("TOTP_SECRET_REGISTER")
	if !exists {
		log.Fatal("Missing env variable \"TOTP_SECRET_REGISTER\"")
	}
	passwordRegisterCode, exists = os.LookupEnv("PASSWORD_REGISTER")
	if !exists {
		log.Fatal("Missing env variable \"PASSWORD_REGISTER\"")
	}
	createTables()
	return
}

func createTables() (err error) {
	//pgxpool should handle pool limits... i think :v
	pool, err := pgxpool.New(ctx, pgURL)
	if err != nil {
		log.Fatalf("Could not connect to database: %v", err.Error())
	}
	defer pool.Close()
	users := `
	CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password TEXT NOT NULL,
		totp TEXT NOT NULL,
		token TEXT NOT NULL
	);
	`
	_, err = pool.Exec(ctx,users)
	if err != nil {
		log.Fatalf("Could not initialize users table: %v", err.Error())
		return
	}
	files := `
	CREATE TABLE IF NOT EXISTS files (
		id SERIAL PRIMARY KEY,
		name TEXT NOT NULL,
		oid OID NOT NULL,
		content_type TEXT NOT NULL,
		owner TEXT REFERENCES users(username)
	);
	`
	_, err = pool.Exec(ctx,files)
	if err != nil {
		log.Fatalf("Could not initialize files table: %v", err.Error())
		return
	}
	return
}

func genToken(username string, password string) string{
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	usernameEncoded := base64.StdEncoding.EncodeToString([]byte(username))
	timeEncoded := base64.StdEncoding.EncodeToString([]byte(time.Now().String()))
	randomSuffix := make([]byte, 10)
	for i := range randomSuffix {
		nBig, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			panic(err)
		}
		randomSuffix[i] = chars[nBig.Int64()]
	}
	key := []byte(password + string(randomSuffix))
	message := []byte(password)
	h := hmac.New(sha256.New, key)
	h.Write(message)
	hash := hex.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("%v.%v.%v.",usernameEncoded,timeEncoded,hash)
}

func Authenticate(username string, password string, totpCode string) (token string, err error) {
	sha256Bytes := sha256.Sum256([]byte(password))
	password = hex.EncodeToString(sha256Bytes[:]) //https://stackoverflow.com/questions/40632802/how-to-convert-byte-array-to-string-in-go
	log.Printf("Someone tried logging in: %v, %v, %v\n",username,password,totpCode)
	var totpSecret string
	pool, err := pgxpool.New(ctx, pgURL)
	if err != nil{
		log.Printf("An error ocurred trying to create pool: %v", err.Error())
		return
	}
	err = pool.QueryRow(ctx, "SELECT token,totp FROM users WHERE username=$1 AND password=$2",username,password).Scan(&token,&totpSecret)
	if err != nil {
		return
	}
	totpCodeGenerated, err := totp.GenerateCode(totpSecret,time.Now())
	if err != nil{
		log.Printf("An error ocurred generating TOTP code: %v", err.Error())
		return
	}
	if totpCodeGenerated != totpCode {
		token = ""
		err = errors.New("invalid TOTP code")
	}
	return
}

func ValidateToken(token string) (err error){
	pool, err := pgxpool.New(ctx, pgURL)
	if err != nil{
		log.Printf("An error ocurred trying to create pool: %v", err.Error())
		return
	}
	err = pool.QueryRow(ctx, "SELECT token FROM users WHERE token=$1",token).Scan(&token)
	return
}

func Register(username string, password string, totpCode string, passwordRegister string) (totpSecret string, err error) {
	sha256Bytes := sha256.Sum256([]byte(password))
	password = hex.EncodeToString(sha256Bytes[:]) //https://stackoverflow.com/questions/40632802/how-to-convert-byte-array-to-string-in-go
	totpCodeGenerated, err := totp.GenerateCode(totpSecretRegister, time.Now())
	if err != nil {
		log.Printf("An error ocurred generating TOTP code: %v", err.Error())
		return
	}
	if totpCodeGenerated != totpCode {
		err = errors.New("invalid TOTP code")
		return
	}
	if passwordRegister != passwordRegisterCode{
		err = errors.New("invalid register password")
		return
	}
	var usernameFetch string
	pool, err := pgxpool.New(ctx, pgURL)
	if err != nil{
		log.Printf("An error ocurred trying to create pool: %v", err.Error())
		return
	}
	err = pool.QueryRow(ctx,"SELECT username FROM users WHERE username = $1",username).Scan(&usernameFetch)
	if err == nil {
		err = errors.New("user already exists")
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer: username,
		AccountName: strings.ToUpper(username),
	})
	totpSecret = key.Secret()
	if err != nil {
		log.Printf("An error ocurred generating TOTP secret: %v", err.Error())
		return
	}
	_,err = pool.Exec(ctx, "INSERT INTO users VALUES ($1, $2, $3, $4)",username,password,totpSecret,genToken(username,password))
	if err != nil {
		log.Printf("An error ocurred saving the user to database: %v",err.Error())
	}
	return
}

func SaveFile(file multipart.File, fileHeader *multipart.FileHeader, token string) (id int, err error) {
	defer file.Close()
	var username string
	pool, err := pgxpool.New(ctx, pgURL)
	if err != nil{
		log.Printf("An error ocurred trying to create pool: %v", err.Error())
		return
	}
	err = pool.QueryRow(ctx,"SELECT username FROM users WHERE token = $1",token).Scan(&username)
	if err != nil{
		id = -1
		return
	}
    tx, err := pool.Begin(ctx)
    if err != nil {
		log.Printf("Could not start transaction: %v", err.Error())
        return
    }
    defer tx.Rollback(ctx)
    var oid uint32
    err = tx.QueryRow(ctx, "SELECT lo_create(0)").Scan(&oid)
    if err != nil {
		log.Printf("Could not create large object: %v", err.Error())
        return
    }
    var fd int
    err = tx.QueryRow(ctx, "SELECT lo_open($1, 131072)", oid).Scan(&fd)
    if err != nil {
		log.Printf("COuld not call INV_WRITE: %v", err.Error())
        return
    }
    buf := make([]byte, 32*1024) // 32 KB 
    for {
        n, readErr := file.Read(buf)
        if n > 0 {
            _, err = tx.Exec(ctx, "SELECT lowrite($1, $2)", fd, buf[:n])
            if err != nil {
				log.Printf("An error ocurred trying to write: %v", err.Error())
                return
            }
        }
        if readErr != nil {
            if readErr == io.EOF {
                break
            }
			log.Printf("An error ocurred trying to read file: %v", err.Error())
            return 0,readErr
        }
    }
    _, err = tx.Exec(ctx, "SELECT lo_close($1)", fd)
    if err != nil {
		log.Printf("An error ocurred trying to close file: %v", err.Error())
        return
    }
    err = tx.QueryRow(ctx, "INSERT INTO files (name, oid, content_type, owner) VALUES ($1, $2, $3, $4) RETURNING id", fileHeader.Filename, oid, fileHeader.Header.Get("Content-Type"),username).Scan(&id)
    if err != nil {
		log.Printf("An error ocurred trying to insert metadata: %v", err.Error())
        return
    }
    return id, tx.Commit(ctx)
}

func ServeFile(w *http.ResponseWriter, id int) (err error) {
        var oid uint32
        var name, contentType string
		pool, err := pgxpool.New(ctx, pgURL)
		if err != nil{
			log.Printf("An error ocurred trying to create pool: %v", err.Error())

			return
		}
        err = pool.QueryRow(ctx,
            `SELECT oid, name, content_type FROM files WHERE id=$1`, id,
        ).Scan(&oid, &name, &contentType)
        if err != nil {
			e := responses.ErrorResponse{Message: "File not found", Ratelimit:0}
			responses.SendResponse(&e, w, http.StatusNotFound)
            return
        }
        tx, err := pool.Begin(ctx)
        if err != nil {
			log.Printf("An error ocurred during transaction: %v", err.Error())
			e := responses.ErrorResponse{Message: "Something wrong happened D:", Ratelimit:0}
			responses.SendResponse(&e, w, http.StatusInternalServerError)
            return
        }
        defer tx.Rollback(ctx)

        var fd int
        err = tx.QueryRow(ctx, "SELECT lo_open($1, 262144)", oid).Scan(&fd) // 262144 = INV_READ
        if err != nil {
			log.Printf("An error ocurred trying to open LargeObject: %v", err.Error())
			e := responses.ErrorResponse{Message: "Something wrong happened D:", Ratelimit:0}
			responses.SendResponse(&e, w, http.StatusInternalServerError)
            return
        }
        buf := make([]byte, 32*1024) // 32 KB
        (*w).Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
        if contentType != "" {
            (*w).Header().Set("Content-Type", contentType)
        } else {
            (*w).Header().Set("Content-Type", "application/octet-stream")
        }

        for {
            var chunk []byte
            err = tx.QueryRow(ctx, "SELECT loread($1, $2)", fd, len(buf)).Scan(&chunk)
            if err != nil {
                if err == io.EOF {
                    break
                }
				log.Printf("An error ocurred trying to read file: %v", err.Error())
				e := responses.ErrorResponse{Message: "Something wrong happened D:", Ratelimit:0}
				responses.SendResponse(&e, w, http.StatusInternalServerError)
                return
            }
            if len(chunk) == 0 {
                break
            }
            (*w).Write(chunk)
        }
        _, err = tx.Exec(ctx, "SELECT lo_close($1)", fd)
        if err != nil {
			log.Printf("An error ocurred trying to close file: %v", err.Error())
			e := responses.ErrorResponse{Message: "Something wrong happened D:", Ratelimit:0}
			responses.SendResponse(&e, w, http.StatusInternalServerError)
            return
        }

        return tx.Commit(ctx)
    }

func GetFileNames(token string) (ids []int, filenames []string, err error) {
	pool, err := pgxpool.New(ctx, pgURL)
	if err != nil{
		log.Printf("An error ocurred trying to create pool: %v", err.Error())
		return
	}
	sql := `SELECT id, name FROM users
			JOIN files ON users.username=files.owner
			WHERE users.token=$1`
	rows,err := pool.Query(ctx,sql,token)
	if err != nil {
		log.Printf("An error ocurred trying to get files: %v", err.Error())
		return
	}
	var id int
	var filename string
	for rows.Next() {
		rows.Scan(&id,&filename)
		ids = append(ids, id)
		filenames = append(filenames, filename)
	}
	return
}

package api

import (
	"filehost/internal/db"
	"filehost/internal/responses"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

var mux = http.NewServeMux()
var maxUploadSize int64
func Listen() error {
	var exists bool
	maxUploadSizeString, exists := os.LookupEnv("MAX_UPLOAD_SIZE")
	if !exists {
		log.Fatal("Missing \"MAX_UPLOAD_SIZE\" env")
	}
	var err error
	maxUploadSize, err = strconv.ParseInt(maxUploadSizeString,10,64)
	if err != nil {
		log.Fatalf("Error trying to set max upload size: %v", err.Error())
	}
	maxUploadSize <<= 20
	mux.HandleFunc("GET /", root)
	mux.HandleFunc("GET /signup", signup)
	mux.HandleFunc("GET /dashboard", dashboard)
	mux.HandleFunc("GET /file/{id}", fetchFile)
	mux.HandleFunc("GET /files", getFiles)
	mux.HandleFunc("POST /auth", auth)
	mux.HandleFunc("POST /validatetoken", validateToken)
	mux.HandleFunc("POST /register", register)
	mux.HandleFunc("POST /upload", upload)
	return http.ListenAndServe("0.0.0.0:80", mux)
}

func root(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w,r,"internal/webfiles/root.html")
}
func signup(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w,r,"internal/webfiles/signup.html")
}
func dashboard(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w,r,"internal/webfiles/dashboard.html")
}

func auth(w http.ResponseWriter, r *http.Request) {
	if IsRateLimited(r.URL.Hostname()){
		e := responses.ErrorResponse{Message: "Ratelimited", Ratelimit: 60} //idc brah
		responses.SendResponse(&e,&w,http.StatusTooManyRequests)
		return
	}
	headers := &r.Header
	username := headers.Get("username")
	password := headers.Get("password")
	totpCode := headers.Get("totp")
	token, err := db.Authenticate(username, password, totpCode) 
	
	if err != nil {
		e := responses.ErrorResponse{Message: "Wrong Credentials", Ratelimit: 0}
		responses.SendResponse(&e,&w,http.StatusUnauthorized)
		log.Printf("Someone tried logging in and failed: %v", err.Error())
		return
	}
	resp := responses.LoginResponse{Token:token}
	responses.SendResponse(&resp,&w,http.StatusOK)
} 

func validateToken(w http.ResponseWriter, r *http.Request) {
	if IsRateLimited(r.URL.Hostname()){
		e := responses.ErrorResponse{Message: "Ratelimited", Ratelimit: 60} //idc brah
		responses.SendResponse(&e,&w,http.StatusTooManyRequests)
		return
	}
	token := r.Header.Get("token")
	log.Printf("Someone tried validating token: %v", token)
	if err := db.ValidateToken(token); err != nil{
		log.Printf("Someone tried validating token and failed: %v", err)
		e := responses.ErrorResponse{Message: "Invalid token", Ratelimit: 0} //idc brah
		responses.SendResponse(&e,&w,http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func register(w http.ResponseWriter, r *http.Request) {
	if IsRateLimited(r.URL.Hostname()){
		e := responses.ErrorResponse{Message: "Ratelimited", Ratelimit: 60} //idc brah
		responses.SendResponse(&e,&w,http.StatusTooManyRequests)
		return
	}
	headers := &r.Header
	username := headers.Get("username")
	password := headers.Get("password")
	totpCodeRegister := headers.Get("totpCodeRegister")
	passwordRegister := headers.Get("passwordRegister")
	totp, err := db.Register(username,password,totpCodeRegister,passwordRegister)
	if err != nil {
		log.Printf("Someone tried registering and failed: %v", err.Error())
		e := responses.ErrorResponse{Message: "Wrong Register Credentials", Ratelimit: 0}
		responses.SendResponse(&e,&w,http.StatusUnauthorized)
		return
	}
	log.Printf("Someone registered, totp secret: %v",totp)
	resp := responses.RegisterResponse{Totp:totp}
	responses.SendResponse(&resp,&w,http.StatusOK)
}

func upload(w http.ResponseWriter, r *http.Request) {
	if IsRateLimited(r.URL.Hostname()){
		e := responses.ErrorResponse{Message: "Ratelimited", Ratelimit: 60} //idc brah
		responses.SendResponse(&e,&w,http.StatusTooManyRequests)
		return
	}
	token := r.Header.Get("token")
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		e := responses.ErrorResponse{Message: fmt.Sprintf("File too large. Max size of %d MB",maxUploadSize), Ratelimit: 0}
		responses.SendResponse(&e,&w,http.StatusRequestEntityTooLarge)
		return
	}
	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		e := responses.ErrorResponse{Message: "Invalid file", Ratelimit: 0}
		responses.SendResponse(&e,&w,http.StatusRequestEntityTooLarge)
		return
	}
	id, err := db.SaveFile(file,fileHeader,token)
	if err != nil {
		if id == -1{
			e := responses.ErrorResponse{Message: "Not authorized", Ratelimit: 0}
			responses.SendResponse(&e,&w,http.StatusUnauthorized)
			return
		}
		e := responses.ErrorResponse{Message: "An error ocurred D:", Ratelimit: 0}
		responses.SendResponse(&e,&w,http.StatusInternalServerError)
		return
	}
	resp := responses.FileUploadedResponse{Id:id}
	responses.SendResponse(&resp,&w,http.StatusOK)
}

func fetchFile(w http.ResponseWriter, r *http.Request){
	if IsRateLimited(r.URL.Hostname()){
		e := responses.ErrorResponse{Message: "Ratelimited", Ratelimit: 60} //idc brah
		responses.SendResponse(&e,&w,http.StatusTooManyRequests)
		return
	}
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil{
		e := responses.ErrorResponse{Message: "Invalid ID", Ratelimit: 0}
		responses.SendResponse(&e,&w,http.StatusBadRequest)
		return
	}
	db.ServeFile(&w, id)
}

func getFiles(w http.ResponseWriter, r *http.Request) {
	if IsRateLimited(r.URL.Hostname()){
		e := responses.ErrorResponse{Message: "Ratelimited", Ratelimit: 60} //idc brah
		responses.SendResponse(&e,&w,http.StatusTooManyRequests)
		return
	}
	token := r.Header.Get("token")
	ids, filenames, err := db.GetFileNames(token)
	if err != nil {
		e := responses.ErrorResponse{Message: "Invalid token", Ratelimit: 0}
		responses.SendResponse(&e,&w,http.StatusUnauthorized)
		return
	}
	resp := responses.UploadedFilesResponse{Ids:ids,Filenames:filenames}
	responses.SendResponse(&resp,&w,http.StatusOK)
}

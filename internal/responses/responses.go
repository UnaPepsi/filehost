package responses

import (
	"net/http"
	"log"
	"encoding/json"
)
type Response interface {
	ErrorResponse | LoginResponse | FileUploadedResponse | RegisterResponse | UploadedFilesResponse
}

type ErrorResponse struct {
	Message string `json:"message"`
	Ratelimit int `json:"ratelimit"`
}

func (e *ErrorResponse) Error() string{
	return e.Message
}

func SendResponse[ResponseType Response](r *ResponseType, w *http.ResponseWriter, statusCode int16){
	(*w).Header().Set("Content-Type", "application/json")
	(*w).WriteHeader(int(statusCode))
	if err := json.NewEncoder(*w).Encode(*r); err != nil{
		log.Fatalf("An error ocurred during json parsing: %v", err.Error())
	}
}
type LoginResponse struct {
	Token string `json:"token"`
}
type RegisterResponse struct {
	Totp string `json:"totp"`
}

type FileUploadedResponse struct {
	Id int `json:"id"`
}

type UploadedFilesResponse struct {
	Ids []int `json:"ids"`
	Filenames []string `json:"filenames"`
}

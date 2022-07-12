package user

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/sha3"

	verifyUser "github.com/goldenrecordstudios-earth/verify_user"
)

type User struct {
	Address  string
	Verified uint8
	Blocked  uint8
	Credits  uint64
	Name     string
	Id       string
	Place    string
	Date     string
}

var secret = os.Getenv("SECRET")

var userAPIScheme = os.Getenv("USER_API_SCHEME")
var userAPIHost = os.Getenv("USER_API_HOST")
var userAPIUri = os.Getenv("USER_API_URI")

var userApiUrl = fmt.Sprintf("%s://%s%s", userAPIScheme, userAPIHost, userAPIUri)

func Auth(r *http.Request) (*User, int, error) {
	user := &User{}

	claim := &verifyUser.Claim{Email: "", Verified: false}
	// pass through the original header containing the token
	statusCode, err := verifyUser.VerifyUser(r, claim)
	if err != nil || statusCode != 200 {
		log.Println(err.Error())
		return user, statusCode, err
	}

	//// calculate id from email
	buf := []byte(claim.Email)
	digest := sha3.Sum224(buf)
	userId := hex.EncodeToString(digest[:])[0:6]

	user.Id = userId

	url := fmt.Sprintf("%s?id=%s", userApiUrl, user.Id)
	body := []byte("")

	request, err := http.NewRequest("GET", url, bytes.NewReader(body))
	if err != nil {
		return user, http.StatusInternalServerError, err
	}

	//// pass through the original header containing the token
	request.Header = r.Header

	httpClient := http.Client{}

	response, err := httpClient.Do(request)
	if err != nil {
		return user, http.StatusBadGateway, err
	}
	defer response.Body.Close()

	bodyRead, err := ioutil.ReadAll(response.Body)
	//DEBUG log.Println("postToUser:")
	//DEBUG log.Println(string(bodyRead))
	if err != nil {
		log.Println(err)
		return user, http.StatusInternalServerError, err
	}

	switch response.StatusCode {
	case 200:
		err = json.Unmarshal(bodyRead, user)
		if err != nil {
			log.Println("error reading user json")
			return user, http.StatusInternalServerError, err
		}
	default:
		// log.Println("user api status code:")
		// log.Println(response.StatusCode)
		err = errors.New(string(bodyRead))
		return user, http.StatusInternalServerError, err
	}

	return user, http.StatusOK, nil
}

func Update(r *http.Request, id string, field string, value int64) (int, error) {

	jsonString := fmt.Sprintf(`{"secret": "%s", "%s": %d}`, secret, field, value)

	body := []byte(jsonString)

	url := fmt.Sprintf("%s?id=%s", userApiUrl, id)

	request, err := http.NewRequest("PUT", url, bytes.NewReader(body))
	if err != nil {
		return http.StatusInternalServerError, err
	}

	//// pass through the original header containing the token
	request.Header = r.Header

	httpClient := http.Client{}

	response, err := httpClient.Do(request)
	if err != nil {
		return http.StatusBadGateway, err
	}
	defer response.Body.Close()

	bodyRead, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	switch response.StatusCode {
	case 200:
		break
	default:
		// log.Println("user api status code:")
		// log.Println(response.StatusCode)
		err = errors.New(string(bodyRead))
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

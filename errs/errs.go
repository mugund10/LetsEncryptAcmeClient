package errs

import "log"

func CheckError(err error) {
	if err != nil {
		log.Println(err)
	}
}

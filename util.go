package ontchain

import "os"

func fileExisted(path string) bool {
	_, err := os.Stat(path)
	return err == nil || os.IsExist(err)
}

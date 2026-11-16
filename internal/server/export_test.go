package server

// CheckMirrorPath exposes the mirror path check to the external tests.
func CheckMirrorPath(rel string) error {
	_, err := localPath(".fetch-test/ns", rel)
	return err
}

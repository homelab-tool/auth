package static

import (
	"encoding/json"
	"io/fs"
	"strings"
)

var urlMap map[string]string

func InitManifest(fsys fs.FS) error {
	data, err := fs.ReadFile(fsys, "manifest.json")
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &urlMap)
}

func StaticURL(path string) string {
	trimmed := strings.TrimPrefix(path, "/")
	if resolved, ok := urlMap[trimmed]; ok {
		return "/static/" + resolved
	}
	return "/static" + path
}

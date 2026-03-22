package adminapi

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static/*
var staticRoot embed.FS

func newAdminStaticHandler() (http.Handler, error) {
	sub, err := fs.Sub(staticRoot, "static")
	if err != nil {
		return nil, err
	}
	return http.StripPrefix("/admin/", http.FileServer(http.FS(sub))), nil
}

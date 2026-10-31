// Package web embeds the dashboard so the server ships as a single binary.
package web

import "embed"

//go:embed static
var FS embed.FS

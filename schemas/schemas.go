// Package schemas embeds the JSON schemas of the knowledge protocol v0,
// so tools and the conformance suite use exactly the published files.
package schemas

import "embed"

// FS holds every *.schema.json file.
//
//go:embed *.schema.json
var FS embed.FS

// Base is the prefix of every schema's $id. It is an identifier; the
// files are the ones in this directory.
const Base = "https://openbasalt.org/schemas/knowledge/v0/"

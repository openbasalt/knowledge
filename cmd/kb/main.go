// Command kb is the tool for publishers, mirrors and clients of the
// knowledge protocol: keys and keyrings, content validation, signed
// builds, verification, local and remote search, pack download, the
// conformance suite and an MCP server over stdio.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/openbasalt/knowledge/client"
	"github.com/openbasalt/knowledge/conformance"
	"github.com/openbasalt/knowledge/internal/build"
	"github.com/openbasalt/knowledge/internal/mcp"
	"github.com/openbasalt/knowledge/internal/source"
	"github.com/openbasalt/knowledge/protocol"
	"github.com/openbasalt/knowledge/signing"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

const usage = `kb: OpenBasalt Knowledge tool (protocol v0)

Keys and trust:
  kb keygen -out KEY.json [-pub PUB.json]
  kb keyring -ns NS -version N -root PUB[,PUB] -publisher PUB[,PUB] [-threshold 1]
             [-revoke KEYID,..] -sign KEY[,KEY] -out KEYRING.json
  kb trust -out TRUST.json KEYRING.json [KEYRING.json..]
  kb delegate -ns NS -key PUBLISHER_KEY -online ONLINE_PUB [-days 30] -out DELEGATION.json

Content:
  kb validate CONTENT_DIR
  kb build -content CONTENT_DIR -key PUBLISHER_KEY -keyring KEYRING.json[,..] -version V -out DIR
  kb verify -trust TRUST.json BUILD_DIR/NS

Search and fetch:
  kb search -bundle BUILD_DIR/NS -trust TRUST.json [query flags]   (local, offline)
  kb query  -url URL -trust TRUST.json [query flags]                (remote)
  kb fetch  -url URL -trust TRUST.json -ns NS -id ID [-lang L]
  kb pack   -url URL -trust TRUST.json -ns NS -id PACK -out FILE
  kb conformance -url URL -trust TRUST.json
  kb mcp (-url URL | -bundle BUILD_DIR/NS) -trust TRUST.json [-ns NS]

Query flags: -ns NS -distro ID -release V -arch A -intent I -component C
  -hw pci:VVVV:DDDD (repeat) -pkg name=version (repeat) -error CODE (repeat)
  -lang L -text TEXT -consent question|topic -limit N -json
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"keygen": keygen, "keyring": keyring, "trust": trust, "delegate": delegate,
		"validate": validate, "build": buildCmd, "verify": verify,
		"search": search, "query": query, "fetch": fetch, "pack": pack,
		"conformance": conformanceCmd, "mcp": mcpCmd,
		"version": func([]string) error { fmt.Println(version); return nil },
	}
	f, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := f(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "kb "+os.Args[1]+":", err)
		os.Exit(1)
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func list(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// writeFile writes atomically with the given mode, refusing to replace an
// existing private key.
func writeFile(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".kb-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	return writeFile(path, append(b, '\n'), mode)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "private key file (written 0600)")
	pub := fs.String("pub", "", "public key file")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	if _, err := os.Stat(*out); err == nil {
		return fmt.Errorf("%s exists; refusing to overwrite a key", *out)
	}
	k, err := signing.GenerateKey(nil)
	if err != nil {
		return err
	}
	b, err := k.MarshalPrivate()
	if err != nil {
		return err
	}
	if err := writeFile(*out, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if *pub != "" {
		if err := writeJSON(*pub, k.Public(), 0o644); err != nil {
			return err
		}
	}
	fmt.Println(k.KeyID())
	return nil
}

func readPublic(path string) (signing.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return signing.PublicKey{}, err
	}
	return signing.ParsePublic(b)
}

func readEnvelope(path string) (*signing.Envelope, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return signing.ParseEnvelope(b)
}

func keyring(args []string) error {
	fs := flag.NewFlagSet("keyring", flag.ExitOnError)
	ns := fs.String("ns", "", "namespace")
	ver := fs.Int("version", 1, "keyring version")
	roots := fs.String("root", "", "root public key files, comma separated")
	pubs := fs.String("publisher", "", "publisher public key files, comma separated")
	threshold := fs.Int("threshold", 1, "root signatures needed for the next version")
	revoke := fs.String("revoke", "", "revoked key ids, comma separated")
	sign := fs.String("sign", "", "private key files that sign this version, comma separated")
	out := fs.String("out", "", "output file")
	_ = fs.Parse(args)
	k := signing.Keyring{Schema: signing.SchemaKeyring, Namespace: *ns, Version: *ver, Threshold: *threshold, Revoked: list(*revoke)}
	add := func(files, role string) error {
		for _, f := range list(files) {
			p, err := readPublic(f)
			if err != nil {
				return err
			}
			merged := false
			for i := range k.Keys {
				if k.Keys[i].KeyID == p.KeyID {
					k.Keys[i].Roles = append(k.Keys[i].Roles, role)
					merged = true
				}
			}
			if !merged {
				k.Keys = append(k.Keys, signing.KeyringKey{PublicKey: p, Roles: []string{role}})
			}
		}
		return nil
	}
	if err := add(*roots, signing.RoleRoot); err != nil {
		return err
	}
	if err := add(*pubs, signing.RolePublisher); err != nil {
		return err
	}
	if err := k.Validate(); err != nil {
		return err
	}
	var signers []*signing.Signer
	for _, f := range list(*sign) {
		s, err := signing.LoadPrivate(f)
		if err != nil {
			return err
		}
		signers = append(signers, s)
	}
	env, err := signing.SealJSON(signing.TypeKeyring, k, signers...)
	if err != nil {
		return err
	}
	if *out == "" {
		return errors.New("-out is required")
	}
	return writeJSON(*out, env, 0o644)
}

func trust(args []string) error {
	fs := flag.NewFlagSet("trust", flag.ExitOnError)
	out := fs.String("out", "", "trust file")
	_ = fs.Parse(args)
	tf := signing.TrustFile{Schema: signing.SchemaTrust}
	for _, f := range fs.Args() {
		env, err := readEnvelope(f)
		if err != nil {
			return err
		}
		tf.Keyrings = append(tf.Keyrings, env)
	}
	b, err := json.Marshal(tf)
	if err != nil {
		return err
	}
	if _, err := signing.ParseTrust(b); err != nil {
		return err
	}
	return writeJSON(*out, tf, 0o644)
}

func delegate(args []string) error {
	fs := flag.NewFlagSet("delegate", flag.ExitOnError)
	ns := fs.String("ns", "", "namespace")
	key := fs.String("key", "", "publisher private key")
	online := fs.String("online", "", "online public key")
	days := fs.Int("days", 30, "validity in days (at most 90)")
	out := fs.String("out", "", "output file")
	_ = fs.Parse(args)
	s, err := signing.LoadPrivate(*key)
	if err != nil {
		return err
	}
	p, err := readPublic(*online)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	d := signing.Delegation{Schema: signing.SchemaDelegation, Namespace: *ns, Key: p,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Duration(*days)*24*time.Hour - time.Hour)}
	if d.NotAfter.Sub(d.NotBefore) > signing.MaxDelegation {
		return errors.New("a delegation lasts at most 90 days")
	}
	env, err := signing.SealJSON(signing.TypeDelegation, d, s)
	if err != nil {
		return err
	}
	return writeJSON(*out, env, 0o644)
}

func validate(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: kb validate CONTENT_DIR")
	}
	src, err := source.Load(args[0])
	if err != nil {
		return err
	}
	fmt.Printf("%s: %d entries valid\n", src.Namespace.Namespace, len(src.Entries))
	return nil
}

func buildTime() (time.Time, error) {
	if s := os.Getenv("SOURCE_DATE_EPOCH"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH: %v", err)
		}
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Now().UTC().Truncate(time.Second), nil
}

func buildCmd(args []string) error {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	content := fs.String("content", "", "namespace content directory")
	key := fs.String("key", "", "publisher private key")
	rings := fs.String("keyring", "", "keyring files, oldest first, comma separated")
	ver := fs.String("version", "", "bundle version, e.g. 2026.10.5")
	out := fs.String("out", "", "output root")
	_ = fs.Parse(args)
	src, err := source.Load(*content)
	if err != nil {
		return err
	}
	s, err := signing.LoadPrivate(*key)
	if err != nil {
		return err
	}
	var envs []*signing.Envelope
	for _, f := range list(*rings) {
		env, err := readEnvelope(f)
		if err != nil {
			return err
		}
		envs = append(envs, env)
	}
	t, err := buildTime()
	if err != nil {
		return err
	}
	res, err := build.Build(src, build.Options{Out: *out, Version: *ver, Created: t, Signer: s, Keyrings: envs})
	if err != nil {
		return err
	}
	fmt.Printf("%s: %d entries\n", res.Dir, res.Entries)
	for _, p := range res.Packs {
		fmt.Printf("  %s %s %d bytes %s\n", p.Path, p.Digest, p.Size, p.Titles["en"])
	}
	return nil
}

func loadBundle(dir, trustFile string) (*build.Namespace, error) {
	tr, err := signing.LoadTrust(trustFile)
	if err != nil {
		return nil, err
	}
	if err := build.FollowKeyrings(dir, tr); err != nil {
		return nil, err
	}
	return build.LoadNamespace(dir, tr)
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	tf := fs.String("trust", "", "trust file")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		return errors.New("usage: kb verify -trust TRUST.json BUILD_DIR/NS")
	}
	n, err := loadBundle(fs.Arg(0), *tf)
	if err != nil {
		return err
	}
	fmt.Printf("%s %s: catalog %s, %d packs, %d entries, all signatures valid\n",
		n.Name, n.Catalog.Version, n.CatalogDigest, len(n.Packs), len(n.Entries))
	return nil
}

type queryFlags struct {
	fs                                                       *flag.FlagSet
	ns, distro, release, arch, intent, component, lang, text *string
	consent                                                  *string
	limit                                                    *int
	asJSON                                                   *bool
	hw, pkg, errs                                            multi
}

func newQueryFlags(name string) *queryFlags {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	q := &queryFlags{fs: fs,
		ns: fs.String("ns", "basalt", "namespace"), distro: fs.String("distro", "", "os-release ID"),
		release: fs.String("release", "", "os-release VERSION_ID"), arch: fs.String("arch", "", "architecture"),
		intent: fs.String("intent", "", "intent identifier"), component: fs.String("component", "", "component identifier"),
		lang: fs.String("lang", "", "language"), text: fs.String("text", "", "free text (needs -consent)"),
		consent: fs.String("consent", "", "question or topic"), limit: fs.Int("limit", 0, "results"),
		asJSON: fs.Bool("json", false, "JSON output")}
	fs.Var(&q.hw, "hw", "bus:vendor:device (repeat)")
	fs.Var(&q.pkg, "pkg", "name=version (repeat)")
	fs.Var(&q.errs, "error", "error code (repeat)")
	return q
}

func (q *queryFlags) request() (protocol.SearchRequest, error) {
	args := map[string]any{"namespace": *q.ns, "distro": *q.distro, "release": *q.release, "arch": *q.arch,
		"intent": *q.intent, "component": *q.component, "lang": *q.lang, "free_text": *q.text,
		"free_text_consent": *q.consent, "limit": float64(*q.limit)}
	toAny := func(m multi) []any {
		var out []any
		for _, v := range m {
			out = append(out, v)
		}
		return out
	}
	args["hardware"], args["packages"], args["errors"] = toAny(q.hw), toAny(q.pkg), toAny(q.errs)
	s := mcp.Server{Namespace: *q.ns}
	return s.BuildRequest(args)
}

func printHits(w io.Writer, hits []mcp.Hit, packs []protocol.PackRef, lang string, asJSON bool) error {
	if asJSON {
		var items []any
		for _, h := range hits {
			items = append(items, mcp.Structured(h.Entry, lang, h.Score, h.Matched))
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", " ")
		return enc.Encode(map[string]any{"results": items, "packs": packs})
	}
	if len(hits) == 0 {
		fmt.Fprintln(w, "no matching entry")
	}
	for _, h := range hits {
		v, _ := h.Entry.Text(lang)
		fmt.Fprintf(w, "%6.2f  %s/%s  [%s]  %s\n        %s\n", h.Score, h.Entry.Namespace, h.Entry.ID,
			strings.Join(h.Matched, ","), v.Title, v.Summary)
	}
	for _, p := range packs {
		fmt.Fprintf(w, "pack available: %s %s (%s)\n", p.ID, p.Version, p.Digest)
	}
	return nil
}

func search(args []string) error {
	q := newQueryFlags("search")
	bundle := q.fs.String("bundle", "", "build directory of one namespace")
	tf := q.fs.String("trust", "", "trust file")
	_ = q.fs.Parse(args)
	n, err := loadBundle(*bundle, *tf)
	if err != nil {
		return err
	}
	req, err := q.request()
	if err != nil {
		return err
	}
	hits, packs, err := mcp.NewLocal(n).Search(context.Background(), req)
	if err != nil {
		return err
	}
	return printHits(os.Stdout, hits, packs, *q.lang, *q.asJSON)
}

func newClient(url, trustFile string) (*client.Client, error) {
	tr, err := signing.LoadTrust(trustFile)
	if err != nil {
		return nil, err
	}
	return client.New(url, tr)
}

func query(args []string) error {
	q := newQueryFlags("query")
	url := q.fs.String("url", "", "server base URL")
	tf := q.fs.String("trust", "", "trust file")
	_ = q.fs.Parse(args)
	c, err := newClient(*url, *tf)
	if err != nil {
		return err
	}
	req, err := q.request()
	if err != nil {
		return err
	}
	hits, packs, err := mcp.Remote{Client: c}.Search(context.Background(), req)
	if err != nil {
		return err
	}
	return printHits(os.Stdout, hits, packs, *q.lang, *q.asJSON)
}

func fetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	url := fs.String("url", "", "server or mirror base URL")
	tf := fs.String("trust", "", "trust file")
	ns := fs.String("ns", "basalt", "namespace")
	id := fs.String("id", "", "entry id")
	lang := fs.String("lang", "", "language")
	_ = fs.Parse(args)
	c, err := newClient(*url, *tf)
	if err != nil {
		return err
	}
	e, err := c.Entry(context.Background(), *ns, *id)
	if err != nil {
		return err
	}
	fmt.Print(mcp.Render(e, *lang, true))
	return nil
}

func pack(args []string) error {
	fs := flag.NewFlagSet("pack", flag.ExitOnError)
	url := fs.String("url", "", "server or mirror base URL")
	tf := fs.String("trust", "", "trust file")
	ns := fs.String("ns", "basalt", "namespace")
	id := fs.String("id", "", "pack id")
	out := fs.String("out", "", "file to keep the verified pack in")
	_ = fs.Parse(args)
	c, err := newClient(*url, *tf)
	if err != nil {
		return err
	}
	ctx := context.Background()
	cat, err := c.Catalog(ctx, *ns)
	if err != nil {
		return err
	}
	for _, cp := range cat.Packs {
		if cp.ID != *id {
			continue
		}
		p, entries, raw, err := c.Pack(ctx, *ns, cp)
		if err != nil {
			return err
		}
		if err := writeFile(*out, raw, 0o644); err != nil {
			return err
		}
		fmt.Printf("%s %s: %d entries verified, %d bytes, %s\n", p.ID, p.Version, len(entries), len(raw), cp.Digest)
		return nil
	}
	return fmt.Errorf("pack %q is not in the catalog", *id)
}

func conformanceCmd(args []string) error {
	fs := flag.NewFlagSet("conformance", flag.ExitOnError)
	url := fs.String("url", "", "server base URL")
	tf := fs.String("trust", "", "trust file")
	_ = fs.Parse(args)
	tr, err := signing.LoadTrust(*tf)
	if err != nil {
		return err
	}
	results, err := conformance.Run(context.Background(), *url, tr, conformance.BasaltFixture())
	if err != nil {
		return err
	}
	for _, r := range results {
		status := "pass"
		if !r.Pass {
			status = "FAIL"
		}
		fmt.Printf("%-4s %-6s %-36s %s\n", status, r.Level, r.ID, r.Detail)
	}
	if f := conformance.Failed(results); len(f) > 0 {
		return fmt.Errorf("%d MUST checks failed", len(f))
	}
	return nil
}

func mcpCmd(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	url := fs.String("url", "", "server base URL (remote mode)")
	bundle := fs.String("bundle", "", "build directory of one namespace (local mode)")
	tf := fs.String("trust", "", "trust file")
	ns := fs.String("ns", "basalt", "default namespace")
	_ = fs.Parse(args)
	srv := &mcp.Server{Namespace: *ns, Name: "openbasalt-knowledge", Version: version}
	switch {
	case *url != "" && *bundle == "":
		c, err := newClient(*url, *tf)
		if err != nil {
			return err
		}
		srv.Backend = mcp.Remote{Client: c}
	case *bundle != "" && *url == "":
		n, err := loadBundle(*bundle, *tf)
		if err != nil {
			return err
		}
		srv.Backend = mcp.NewLocal(n)
	default:
		return errors.New("give either -url or -bundle")
	}
	return srv.Serve(context.Background(), os.Stdin, os.Stdout)
}

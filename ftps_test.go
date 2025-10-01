// Copyright 2020 Daniel Theophanes.
// Use of this source code is governed by a zlib-style
// license that can be found in the LICENSE file.

package ftps

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fclairamb/ftpserver/server"
	"github.com/spf13/afero/mem"
	"golang.org/x/net/context"
)

func TestRemote(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	var serverURL = os.Getenv("SERVER_URL") // "ftps://username:password@hostname:990?explicit=bool"

	if len(serverURL) == 0 {
		t.Skip("Missing SERVER_URL to test remote")
	}

	su, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	if p, err := strconv.ParseInt(su.Port(), 10, 32); err == nil {
		port = int(p)
	}
	u, p := "", ""
	if su.User != nil {
		u = su.User.Username()
		p, _ = su.User.Password()
	}
	explicit, _ := strconv.ParseBool(su.Query().Get("explicit"))
	InsecureUnencrypted, _ := strconv.ParseBool(su.Query().Get("insecure-unencrypted"))

	c, err := Dial(ctx, DialOptions{
		Host:     su.Hostname(),
		Port:     port,
		Username: u,
		Passowrd: p,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ExplicitTLS:         explicit,
		InsecureUnencrypted: InsecureUnencrypted,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	const upload = false
	if upload {
		const (
			f1Name    = "f1"
			f1Content = "hello world"
		)
		if err = c.Upload(ctx, f1Name, strings.NewReader(f1Content)); err != nil {
			t.Fatal(err)
		}
		defer c.RemoveFile(f1Name)

		f1Buff := &bytes.Buffer{}
		if err = c.Download(ctx, f1Name, f1Buff); err != nil {
			t.Fatal(err)
		}
		if w, g := f1Content, f1Buff.String(); w != g {
			t.Fatalf("want %q, got %q", w, g)
		}
	}

	list, err := c.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range list {
		t.Log(item)
	}
	if upload {
		if g, w := len(list), 1; g != w {
			t.Fatalf("got %d items, want %d", g, w)
		}
	}

	err = c.Close()
	if err != nil {
		t.Fatal(err)
	}
}

type testDriver struct {
	l    net.Listener
	cert tls.Certificate
	te   *testHandler
}

var _ server.MainDriver = testDriver{}

func (d testDriver) GetSettings() (*server.Settings, error) {
	return &server.Settings{
		Listener: d.l,
	}, nil
}
func (testDriver) WelcomeUser(cc server.ClientContext) (string, error) { return "", nil }
func (testDriver) UserLeft(cc server.ClientContext)                    {}
func (d testDriver) AuthUser(cc server.ClientContext, user, pass string) (server.ClientHandlingDriver, error) {
	return d.te, nil
}
func (d testDriver) GetTLSConfig() (*tls.Config, error) {
	return &tls.Config{
		Certificates: []tls.Certificate{
			d.cert,
		},
		InsecureSkipVerify: true,
	}, nil
}

type te struct {
	dir bool
	fd  *mem.FileData
}

type testHandler struct {
	cwd string
	all map[string]*te
}

var _ server.ClientHandlingDriver = &testHandler{}

func (h *testHandler) ChangeDirectory(cc server.ClientContext, directory string) error {
	cwd := h.path(directory)
	if x, ok := h.all[cwd]; ok && x.dir {
		return nil
	}
	return nil
}
func (h *testHandler) MakeDirectory(cc server.ClientContext, directory string) error {
	directory = h.path(directory)
	_, ok := h.all[directory]
	if ok {
		return os.ErrExist
	}
	_, name := path.Split(directory)
	h.all[directory] = &te{dir: true, fd: mem.CreateDir(name)}
	return nil
}

func (h *testHandler) ListFiles(cc server.ClientContext, directory string) ([]os.FileInfo, error) {
	directory = h.path(directory)
	list := []os.FileInfo{}
	for key, item := range h.all {
		if !strings.HasPrefix(key, directory) {
			continue
		}
		if key == directory {
			continue
		}

		list = append(list, mem.GetFileInfo(item.fd))
	}
	return list, nil
}

func (h *testHandler) OpenFile(cc server.ClientContext, p string, flag int) (server.FileStream, error) {
	p = h.path(p)
	x, ok := h.all[p]
	if !ok {
		_, name := path.Split(p)
		x = &te{
			fd: mem.CreateFile(name),
		}
		h.all[p] = x
	}
	return mem.NewFileHandle(x.fd), nil
}
func (h *testHandler) DeleteFile(cc server.ClientContext, path string) error {
	path = h.path(path)
	_, ok := h.all[path]
	if !ok {
		return os.ErrNotExist
	}
	delete(h.all, path)
	return nil
}
func (h *testHandler) GetFileInfo(cc server.ClientContext, p string) (os.FileInfo, error) {
	p = h.path(p)
	x, ok := h.all[p]
	if !ok {
		return nil, os.ErrNotExist
	}
	return mem.GetFileInfo(x.fd), nil
}
func (h *testHandler) SetFileMtime(cc server.ClientContext, path string, mtime time.Time) error {
	return nil
}
func (h *testHandler) path(p string) string {
	return path.Clean(path.Join(h.cwd, p))
}
func (h *testHandler) RenameFile(cc server.ClientContext, from, to string) error {
	from = h.path(from)
	to = h.path(to)
	x, ok := h.all[from]
	if !ok {
		return os.ErrNotExist
	}
	h.all[to] = x
	delete(h.all, from)

	return nil
}
func (h *testHandler) CanAllocate(cc server.ClientContext, size int) (bool, error) { return true, nil }
func (h *testHandler) ChmodFile(cc server.ClientContext, path string, mode os.FileMode) error {
	return nil
}

func TestScript(t *testing.T) {
	sl, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair([]byte(testCert), []byte(testKey))
	if err != nil {
		t.Fatal(err)
	}

	td := testDriver{
		l:    sl,
		cert: cert,
		te: &testHandler{
			all: map[string]*te{},
		},
	}
	s := server.NewFtpServer(td)
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	go func() {
		s.Serve()
	}()

	port := sl.Addr().(*net.TCPAddr).Port

	c, err := Dial(ctx, DialOptions{
		Host:        "localhost",
		Port:        port,
		ExplicitTLS: true,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err = c.Mkdir("d1"); err != nil {
		t.Fatal(err)
	}
	if err = c.Chdir("d1"); err != nil {
		t.Fatal(err)
	}

	const (
		f1Name    = "f1"
		f1Content = "hello world"
	)
	if err = c.Upload(ctx, f1Name, strings.NewReader(f1Content)); err != nil {
		t.Fatal(err)
	}
	f1Buff := &bytes.Buffer{}
	if err = c.Download(ctx, f1Name, f1Buff); err != nil {
		t.Fatal(err)
	}
	if w, g := f1Content, f1Buff.String(); w != g {
		t.Fatalf("want %q, got %q", w, g)
	}

	list, err := c.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range list {
		t.Log(item)
	}
	if g, w := len(list), 1; g != w {
		t.Fatalf("got %d items, want %d", g, w)
	}

	if err = c.Chdir("/"); err != nil {
		t.Fatal(err)
	}
	if err = c.Mkdir("d2"); err != nil {
		t.Fatal(err)
	}
	if err = c.Chdir("d2"); err != nil {
		t.Fatal(err)
	}
	list, err = c.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Check the zero case to verify data channel can be closed right away.
	if g, w := len(list), 0; g != w {
		t.Fatalf("got %d items, want %d", g, w)
	}

	err = c.Close()
	if err != nil {
		t.Fatal(err)
	}
}

const (
	testKey = `-----BEGIN PRIVATE KEY-----
MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQDfWOMyCDYzf/wD
SS2KTNV09DCClQgbrG0VA/uO5TDFH8Auma+ael34wl075M6SPZiiIj/CKsdv4Jnv
mfFDDOTQZ0mfUUhiPovOWv9JxRUdg/ASTyRyxQSp5Mjb+TdN0T6Dl9ohMaza7dlG
L93uLI2N9RVeGAKH47+BT4BRZ010jxvZFw/3jNIwDHkEPkZ28JhQQ6JlZiHZLbWH
Jh9kRBnzovzDXLLb4aKRHwFkUSyPfJJkRteuNYmSwhirzxtqj6soq10QbP7i59sy
iyrU9k7xYhGO3AtBhGK+cXjRFUTEVfJ+sHwk4+2hH6UwS6aVL5Bz9v+2DtK/igsf
nKHvw9gJAgMBAAECggEATzUsza+P2U/IRjoLhoKdKO74zTahO3846D0TV6f8Vcxe
0af7WOOQtAnqGrWYdNCXctiGmAun0wtqTEjiAQ9vjmEzAOdIrl7UIgivhK/6Pw9t
cnDS0kkA0GesvCZz8IsGipCt8Ru226WCapvLLw5p3TBPtaD6NMsWPXu+XCAwnecB
L0sIK1A8KzMc5Wo2gJnIVzLuHE6T7eNpB81XfTSMjkLSFYYcbB4+8jxm8smmmvjc
jGuTgLtouGp3DyvCduSSTgoEQL6+P/G/d575oXvIeJbHXjy6Kd4ia0Ig6cm79T0g
sGJRNhSvDDKix00wVWyJ6zFu41tTda7BMbUtWYgLqQKBgQDy/QTiOPIskb18UkmC
orHHGe7N8jQzUD7dayh1hDNJrNqzziOu57UaH5IbZ68rgFYmdu4HwL2U4it3lYwS
93wPn7odPzSJu2cU3xCsHEaONvmWV0dR95fJxGzlY06yNG8cV4XgFyf2TKsOIo1N
MK0uhENjXZLymZ76dnb66dT9ewKBgQDrTp6vpXFCj1CM01ytVBO3zUheeHl1JkWg
72ZgKO/+LRpzHiaOP/f7XS4/losfYukZD8bqGELT4/J5aqVw4dl1qQNgQfn44XNX
7FsAbHNIk9JJmK8h2rIx/1IjbxF5ZOk3arJQLlxICOYu7EJ70Tw6J55aDSoBqk+H
s2iWUTwvSwKBgGCJP0h1IVmtqR9cPdJFuuWEGwj9IdoFFoS3TwKpPAsYPmdTDYAu
lBfF1TFIFyLsQM3VUCoKXAdrd6Nx6Y2bf1FhvvphowjZSFHVcXU/YpSbqLse/7nD
6S0C+dSEiL5p8H7NEuX9rSXAPfFGruas4RDrAS7X/Uqe17dgG1MCVVlDAn80ZEzw
zuVo7IAC2wzHivDY+9whLLHeY6cdLjCdOIA3F9PLzerHwXZ1gUnK3robQuqjqd+g
P8ahZx+V6Sjs+Vxx1i/qPsZpo8kKypV4gq0oe8FWoahc4VTLzQ181j4NyWoj7J3H
PItPfqvBxtkGuI+wYyHe6w9vT3xluoyO64d7AoGARSoxNk+4Tj/LHLbqK8Z9iPUh
a0g7nJp42nDQ+9EH76ERND8VmNjRdRbHJqSmUzrpvhiYTXvgqNFGHO/VAeVnDhT7
YO5UL8nY1kLOwgk8YnPYBVyYToiOid054n1k7oo4DgIXiHT3DkX88AAI2lU/563C
yIABm9rPqZNdveQksCk=
-----END PRIVATE KEY-----
`
	testCert = `-----BEGIN CERTIFICATE-----
MIIDODCCAiCgAwIBAgIRAMJZEn6aq4ZdJwE1nRbK8PkwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAgFw03MDAxMDEwMDAwMDBaGA8yMDg0MDEyOTE2
MDAwMFowEjEQMA4GA1UEChMHQWNtZSBDbzCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAN9Y4zIINjN//ANJLYpM1XT0MIKVCBusbRUD+47lMMUfwC6Zr5p6
XfjCXTvkzpI9mKIiP8Iqx2/gme+Z8UMM5NBnSZ9RSGI+i85a/0nFFR2D8BJPJHLF
BKnkyNv5N03RPoOX2iExrNrt2UYv3e4sjY31FV4YAofjv4FPgFFnTXSPG9kXD/eM
0jAMeQQ+RnbwmFBDomVmIdkttYcmH2REGfOi/MNcstvhopEfAWRRLI98kmRG1641
iZLCGKvPG2qPqyirXRBs/uLn2zKLKtT2TvFiEY7cC0GEYr5xeNEVRMRV8n6wfCTj
7aEfpTBLppUvkHP2/7YO0r+KCx+coe/D2AkCAwEAAaOBhjCBgzAOBgNVHQ8BAf8E
BAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQUNWPste8lc2VMaDmaWTo5vb21IOswLAYDVR0RBCUwI4IJbG9jYWxob3N0
hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMA0GCSqGSIb3DQEBCwUAA4IBAQCcvXFD
jy+51DuyskX8OwDe9OGnUWwfM2Slu6lWFDUtrPEVpmd+z3lQ8tG+PCXbe97TKdm+
3g8x2pHrwmQ1XeetFcXKBhY06cdPEm/AJ62T67TcePZ2lkCn4jmpQeF4P84FTgX5
fXyRWj3ZNtHEznevxe/QpNJmHBuNIP0s8XZdQ34QYA2uj6NzrY++kS489jcXv72m
W1eIJL56rNWDifmW2wwIo8eVYZo2C5ArbsQcr83DqCBTbPD8BUMkt84HPeyXA63P
qjl7pxtYem5CAG0ncemc9JdYOBj7TolGxiHZbCjCItSuuqmQa5fkq+aaCeq/Vey6
pLMQVkJ0n5+40fet
-----END CERTIFICATE-----
`
)

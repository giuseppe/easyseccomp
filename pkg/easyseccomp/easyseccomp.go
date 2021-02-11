package easyseccomp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"

	spec "github.com/opencontainers/runtime-spec/specs-go"
)

type LoadProfileOptions struct {
	TmpDir          string
	MaxCacheEntries int
}

func maybePruneCache(tmpdir string, maxEntries int) error {
	if maxEntries == 0 {
		maxEntries = 100
	}
	if tmpdir == "" {
		return nil
	}

	st, err := os.Stat(tmpdir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
	}

	s := st.Sys()
	if s == nil {
		return fmt.Errorf("error stat %q", tmpdir)
	}

	ndirs := int(s.(*syscall.Stat_t).Nlink) - 2
	if ndirs < maxEntries {
		return nil
	}

	dirs, err := ioutil.ReadDir(tmpdir)
	if err != nil {
		return err
	}

	for _, d := range dirs {
		os.RemoveAll(filepath.Join(tmpdir, d.Name()))
		ndirs--
		if ndirs < maxEntries {
			return nil
		}
	}
	return nil
}

func checkCache(tmpdir, profile string, caps []string, arch string) (string, []byte, error) {
	if tmpdir == "" {
		return "", nil, nil
	}
	h := sha256.New()
	h.Write([]byte(profile))
	for _, i := range caps {
		h.Write([]byte(i))
	}
	h.Write([]byte(arch))

	parent := filepath.Join(tmpdir, fmt.Sprintf("%x", h.Sum(nil)))
	cacheFile := filepath.Join(parent, "bpf")

	statProfile, err := os.Stat(profile)
	if err != nil {
		return cacheFile, nil, err
	}

	c, err := os.Open(cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return cacheFile, nil, nil
		}
		return cacheFile, nil, err
	}
	defer c.Close()

	st, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", c.Fd()))
	if err != nil {
		return cacheFile, nil, err
	}

	if statProfile.ModTime().After(st.ModTime()) {
		// invalid cache
		os.RemoveAll(parent)
		return cacheFile, nil, nil
	}

	out := make([]byte, st.Size())
	n, err := io.ReadFull(c, out)
	if int64(n) != st.Size() {
		return cacheFile, nil, fmt.Errorf("invalid read from %q", cacheFile)
	}
	return cacheFile, out, err
}

func compile(profile string, caps []string, arch string) ([]byte, error) {
	var defines []string
	for _, cap := range caps {
		defines = append(defines, "--define", cap)
	}
	defines = append(defines, "--define", arch)
	profileData, err := ioutil.ReadFile(profile)
	if err != nil {
		return nil, err
	}
	out := bytes.Buffer{}
	cmd := exec.Command("easyseccomp", defines...)
	cmd.Stdin = bytes.NewBuffer(profileData)
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func LoadProfile(profile string, configSpec *spec.Spec, options *LoadProfileOptions) (*spec.LinuxSeccomp, map[string]string, error) {
	arch := fmt.Sprintf("ARCH_%s", strings.ToUpper(runtime.GOARCH))

	caps := configSpec.Process.Capabilities.Effective[:]
	sort.Strings(caps)

	cacheFile, out, err := checkCache(options.TmpDir, profile, caps, arch)
	if err != nil {
		return nil, nil, err
	}

	// There is no file in the cache, compile it
	if out == nil {
		out, err = compile(profile, caps, arch)
		if err != nil {
			return nil, nil, err
		}
		if cacheFile != "" {
			if err := maybePruneCache(options.TmpDir, options.MaxCacheEntries); err != nil {
				return nil, nil, err
			}
			if err := os.MkdirAll(filepath.Dir(cacheFile), 0700); err != nil {
				return nil, nil, err
			}
			if err := ioutil.WriteFile(cacheFile, out, 0700); err != nil {
				return nil, nil, err
			}
		}
	}

	bpf := base64.StdEncoding.EncodeToString(out)

	// for now it is supported only with crun.
	annotations := map[string]string{
		"run.oci.seccomp_bpf_data": bpf,
	}
	return nil, annotations, nil
}

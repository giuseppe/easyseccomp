package easyseccomp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os/exec"
	"runtime"
	"strings"

	spec "github.com/opencontainers/runtime-spec/specs-go"
)

func LoadProfile(profile string, configSpec *spec.Spec) (*spec.LinuxSeccomp, map[string]string, error) {
	var defines []string

	for _, cap := range configSpec.Process.Capabilities.Effective {
		defines = append(defines, "--define", cap)
	}
	arch := fmt.Sprintf("ARCH_%s", strings.ToUpper(runtime.GOARCH))
	defines = append(defines, "--define", arch)

	profileData, err := ioutil.ReadFile(profile)
	if err != nil {
		return nil, nil, err
	}
	out := bytes.Buffer{}
	cmd := exec.Command("easyseccomp", defines...)
	cmd.Stdin = bytes.NewBuffer(profileData)
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, nil, err
	}
	bpf := base64.StdEncoding.EncodeToString(out.Bytes())

	// for now it is supported only with crun.
	annotations := map[string]string{
		"run.oci.seccomp_bpf_data": bpf,
	}
	return nil, annotations, nil
}

package trustedrouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// LauncherLaunchDescriptor owns delivery; the workload never invents a start insertId.
type startupLaunchDescriptor struct {
	Instance string `json:"instance"`
	Launch   string `json:"launch"`
	Role     string `json:"role"`
	Revision string `json:"revision"`
	Region   string `json:"region"`
}

func (d startupLaunchDescriptor) valid() bool {
	return startupID.MatchString(d.Instance) && startupID.MatchString(d.Launch) && d.Role == "enclave" && startupRevision.MatchString(d.Revision) && startupID.MatchString(d.Region)
}
func readStartupDescriptor(ctx context.Context, r io.ReadCloser) (startupLaunchDescriptor, error) {
	type result struct {
		raw []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() {
			if recover() != nil {
				done <- result{err: errStartupRecord}
			}
		}()
		raw, err := io.ReadAll(io.LimitReader(r, 2049))
		done <- result{raw, err}
	}()
	defer r.Close()
	var d startupLaunchDescriptor
	select {
	case <-ctx.Done():
		return d, errStartupRecord
	case got := <-done:
		if got.err != nil || len(got.raw) > 2048 || !shadowExactObject(got.raw, &d) || !d.valid() {
			return startupLaunchDescriptor{}, errStartupRecord
		}
		return d, nil
	}
}

// Capture fd 3 before listeners can reuse that number. Absence permits the
// instance-as-launch fallback; a present but malformed descriptor does not.
func inheritedStartupDescriptor() (*os.File, bool) {
	var stat syscall.Stat_t
	if syscall.Fstat(3, &stat) != nil {
		return nil, false
	}
	// Make inherited pipes cancellable through os.File's poller.
	if syscall.SetNonblock(3, true) != nil {
		return nil, true
	}
	return os.NewFile(3, "startup-launch-descriptor"), true
}
func startupScoped(source string, coordinate map[string]string, prefix string) string {
	raw, _ := canonicalShadow(map[string]any{"source": source, "coordinate": coordinate})
	sum := sha256.Sum256(raw)
	return prefix + hex.EncodeToString(sum[:])
}

type startupLaunchAcquisition struct {
	descriptor         startupLaunchDescriptor
	mode               string
	coordinate         map[string]string
	startInsertIDKnown bool
}

func startupInstanceLaunch(project, zone, instance, vmBoot, revision, region string) (startupLaunchAcquisition, error) {
	d := startupLaunchDescriptor{Role: "enclave", Revision: revision, Region: region}
	for _, v := range []string{project, zone, vmBoot} {
		if !startupID.MatchString(v) {
			return startupLaunchAcquisition{}, errStartupRecord
		}
	}
	if !regexp.MustCompile(`^[0-9]{1,128}$`).MatchString(instance) {
		return startupLaunchAcquisition{}, errStartupRecord
	}
	coordinate := map[string]string{"project": project, "zone": zone, "instance_id": instance}
	d.Instance = startupScoped("launcher_start", coordinate, "instance:")
	// Without start_insert_id the only available launch is the scoped instance.
	// vm_boot_id is retained separately; this mode needs the external one-start join.
	d.Launch = "launch:" + strings.TrimPrefix(d.Instance, "instance:")
	coordinate["vm_boot_id"] = vmBoot
	if !d.valid() {
		return startupLaunchAcquisition{}, errStartupRecord
	}
	return startupLaunchAcquisition{d, "instance-as-launch", coordinate, false}, nil
}
func startupMetadata(ctx context.Context, client *http.Client, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://metadata.google.internal/computeMetadata/v1/"+path, nil)
	if err != nil {
		return "", errStartupRecord
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return "", errStartupRecord
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 513))
	if err != nil || resp.StatusCode != 200 || len(raw) > 512 {
		return "", errStartupRecord
	}
	return string(raw), nil
}
func acquireStartupLaunch(ctx context.Context, fd *os.File, present bool, revision, region string) (startupLaunchAcquisition, error) {
	if present {
		if fd == nil {
			return startupLaunchAcquisition{}, errStartupRecord
		}
		d, err := readStartupDescriptor(ctx, fd)
		return startupLaunchAcquisition{descriptor: d, mode: "fd3"}, err
	}
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("startup redirect") }}
	project, err := startupMetadata(ctx, client, "project/project-id")
	if err != nil {
		return startupLaunchAcquisition{}, err
	}
	zone, err := startupMetadata(ctx, client, "instance/zone")
	if err != nil {
		return startupLaunchAcquisition{}, err
	}
	parts := strings.Split(zone, "/")
	zone = parts[len(parts)-1]
	instance, err := startupMetadata(ctx, client, "instance/id")
	if err != nil {
		return startupLaunchAcquisition{}, err
	}
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(raw) > 128 {
		return startupLaunchAcquisition{}, errStartupRecord
	}
	return startupInstanceLaunch(project, zone, instance, strings.TrimSpace(string(raw)), revision, region)
}

func readStartupJSON(path string, limit int, into any) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errStartupRecord
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, errStartupRecord
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(raw) > limit {
		return nil, errStartupRecord
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(into) != nil {
		return nil, errStartupRecord
	}
	canonical, err := canonicalShadow(into)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, errStartupRecord
	}
	return raw, nil
}

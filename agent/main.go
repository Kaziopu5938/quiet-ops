// panel-agentd is the deliberately narrow privileged seam for host changes.
// The control plane sends typed JSON operations over a mode-restricted Unix
// socket. There is no arbitrary shell endpoint: every live command below is
// assembled from validated site metadata and a fixed executable/argument list.
package main

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Request struct {
	Action string         `json:"action"`
	SiteID string         `json:"siteId"`
	Spec   map[string]any `json:"spec"`
}

type Response struct {
	OK       bool           `json:"ok"`
	Action   string         `json:"action,omitempty"`
	SiteID   string         `json:"siteId,omitempty"`
	DryRun   bool           `json:"dryRun"`
	Observed map[string]any `json:"observed,omitempty"`
	Error    string         `json:"error,omitempty"`
}

type Config struct {
	Socket          string
	SiteRoot        string
	GeneratedRoot   string
	NginxConfigRoot string
	OlsConfigRoot   string
	UnitRoot        string
	PhpFpmPoolRoot  string
	CronRoot        string
	Live            bool
}

var allowedActions = map[string]bool{
	"preview": true, "converge": true, "observe": true, "publish-release": true,
	"deprovision": true, "reload-nginx": true, "reload-ols": true,
	"start-runtime": true, "stop-runtime": true, "restart-runtime": true, "issue-certificate": true, "provision-data-service": true, "prepare-release": true, "workspace": true,
	"backup-data-service":      true,
	"restore-data-service":     true,
	"deprovision-data-service": true,
	"install-ssh-key":          true,
	"install-cron":             true,
	"remove-cron":              true,
}

func sitePath(root, siteID string) (string, error) {
	if !validSiteID(siteID) {
		return "", errors.New("invalid site id")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	target := filepath.Join(root, siteID)
	if target != root && !strings.HasPrefix(target, root+string(os.PathSeparator)) {
		return "", errors.New("path escapes site root")
	}
	return target, nil
}

func validSiteID(siteID string) bool {
	if len(siteID) < 3 || len(siteID) > 64 || strings.Contains(siteID, "..") {
		return false
	}
	for index, character := range siteID {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' {
			if index == 0 && (character == '_' || character == '-') {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func safeName(siteID string) string {
	name := strings.NewReplacer("-", "", "_", "", ".", "").Replace(siteID)
	if len(name) > 24 {
		name = name[:24]
	}
	return "qops_" + name
}

func stringValue(spec map[string]any, key string) string {
	value, _ := spec[key].(string)
	return strings.TrimSpace(value)
}

func integerValue(spec map[string]any, key string, fallback, minimum, maximum int) (int, error) {
	value := fallback
	switch raw := spec[key].(type) {
	case int:
		value = raw
	case int64:
		value = int(raw)
	case float64:
		value = int(raw)
	case string:
		if raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil {
				return 0, fmt.Errorf("%s must be numeric", key)
			}
			value = parsed
		}
	}
	if value < minimum || value > maximum {
		return 0, fmt.Errorf("%s is outside the supported range", key)
	}
	return value, nil
}

func workload(spec map[string]any) (string, string, error) {
	typeName := stringValue(spec, "type")
	stack := stringValue(spec, "stack")
	if typeName == "" {
		typeName = "static"
	}
	if stack == "" {
		stack = "nginx"
	}
	validType := map[string]bool{"static": true, "wordpress": true, "next": true, "node": true}
	validStack := map[string]bool{"nginx": true, "ols": true, "node": true}
	if !validType[typeName] || !validStack[stack] {
		return "", "", errors.New("invalid workload type or stack")
	}
	if (typeName == "wordpress" && stack == "node") || ((typeName == "next" || typeName == "node") && stack != "node") {
		return "", "", errors.New("workload and stack are incompatible")
	}
	if typeName == "static" && stack != "nginx" {
		return "", "", errors.New("static workloads require nginx")
	}
	return typeName, stack, nil
}

func boundedText(value string, max int, label string) (string, error) {
	if len(value) > max {
		return "", fmt.Errorf("%s exceeds %d bytes", label, max)
	}
	if strings.IndexByte(value, 0) >= 0 {
		return "", fmt.Errorf("%s contains a NUL byte", label)
	}
	return value, nil
}

func relativeSitePath(root, candidate string) (string, error) {
	if candidate == "" {
		return "", errors.New("path is required")
	}
	absolute, err := filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, absolute)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.IsAbs(relative) {
		return "", errors.New("path is outside the site root")
	}
	// Lexical containment is not enough when a release or workspace contains
	// a symlink. Resolve the nearest existing ancestor and keep it under the
	// real site root before any privileged operation follows the path.
	if realRoot, rootErr := filepath.EvalSymlinks(root); rootErr == nil {
		cursor := absolute
		for !pathExists(cursor) && cursor != root {
			cursor = filepath.Dir(cursor)
		}
		if realCursor, cursorErr := filepath.EvalSymlinks(cursor); cursorErr != nil || (realCursor != realRoot && !strings.HasPrefix(realCursor, realRoot+string(os.PathSeparator))) {
			return "", errors.New("path symlink escapes site root")
		}
	}
	return absolute, nil
}

func pathExists(filename string) bool {
	_, err := os.Lstat(filename)
	return err == nil
}

func validateRequest(req Request, cfg Config) (string, string, string, error) {
	root, err := sitePath(cfg.SiteRoot, req.SiteID)
	if err != nil {
		return "", "", "", err
	}
	typeName, stack, err := workload(req.Spec)
	if err != nil {
		return "", "", "", err
	}
	if _, err := boundedText(stringValue(req.Spec, "nginxConfig"), 512*1024, "nginx config"); err != nil {
		return "", "", "", err
	}
	if _, err := boundedText(stringValue(req.Spec, "olsConfig"), 512*1024, "ols config"); err != nil {
		return "", "", "", err
	}
	if req.Action == "issue-certificate" {
		if _, err := certificateDomains(req.Spec); err != nil {
			return "", "", "", err
		}
	}
	if req.Action == "provision-data-service" {
		engine := stringValue(req.Spec, "engine")
		if engine != "mariadb" && engine != "postgresql" && engine != "redis" {
			return "", "", "", errors.New("unsupported data-service engine")
		}
		if !identifier(stringValue(req.Spec, "database")) || !identifier(stringValue(req.Spec, "username")) {
			return "", "", "", errors.New("database and username must be safe identifiers")
		}
	}
	if req.Action == "prepare-release" {
		repository := stringValue(req.Spec, "repo")
		if !strings.HasPrefix(repository, "https://") || strings.ContainsAny(repository, " \t\r\n\x00") {
			return "", "", "", errors.New("live Git deployments require an HTTPS repository URL")
		}
		parsed, parseErr := url.Parse(repository)
		if parseErr != nil || parsed.User != nil {
			return "", "", "", errors.New("Git credentials must use the protected credential store")
		}
		if _, err := relativeSitePath(root, stringValue(req.Spec, "releasePath")); err != nil {
			return "", "", "", err
		}
		build := stringValue(req.Spec, "build")
		if build != "" && build != "none" && build != "node" && build != "next" {
			return "", "", "", errors.New("unsupported build profile")
		}
		credentialKind := stringValue(req.Spec, "credentialKind")
		credentialSecret := stringValue(req.Spec, "credentialSecret")
		if credentialKind != "" && credentialKind != "https-token" {
			return "", "", "", errors.New("unsupported Git credential kind")
		}
		if credentialSecret != "" && (len(credentialSecret) > 4096 || strings.ContainsAny(credentialSecret, "\r\n\x00")) {
			return "", "", "", errors.New("Git credential value is invalid")
		}
	}
	if req.Action == "workspace" {
		if _, err := workspaceCommand(req.Spec); err != nil {
			return "", "", "", err
		}
	}
	if req.Action == "backup-data-service" {
		engine := stringValue(req.Spec, "engine")
		if engine != "mariadb" && engine != "postgresql" && engine != "redis" {
			return "", "", "", errors.New("unsupported data-service engine")
		}
		if !identifier(stringValue(req.Spec, "database")) || !identifier(stringValue(req.Spec, "username")) {
			return "", "", "", errors.New("database and username must be safe identifiers")
		}
		if _, err := relativeSitePath(root, stringValue(req.Spec, "outputPath")); err != nil {
			return "", "", "", err
		}
	}
	if req.Action == "restore-data-service" {
		engine := stringValue(req.Spec, "engine")
		if engine != "mariadb" && engine != "postgresql" && engine != "redis" {
			return "", "", "", errors.New("unsupported data-service engine")
		}
		if !identifier(stringValue(req.Spec, "database")) || !identifier(stringValue(req.Spec, "username")) {
			return "", "", "", errors.New("database and username must be safe identifiers")
		}
		if _, err := relativeSitePath(root, stringValue(req.Spec, "inputPath")); err != nil {
			return "", "", "", err
		}
	}
	if req.Action == "deprovision-data-service" {
		engine := stringValue(req.Spec, "engine")
		if engine != "mariadb" && engine != "postgresql" && engine != "redis" {
			return "", "", "", errors.New("unsupported data-service engine")
		}
		if !identifier(stringValue(req.Spec, "database")) || !identifier(stringValue(req.Spec, "username")) {
			return "", "", "", errors.New("database and username must be safe identifiers")
		}
	}
	if req.Action == "install-cron" {
		if !identifier(stringValue(req.Spec, "cronId")) || !cronExpression(stringValue(req.Spec, "expression")) {
			return "", "", "", errors.New("cron id or expression is invalid")
		}
		if _, err := cronCommand(stringValue(req.Spec, "command")); err != nil {
			return "", "", "", err
		}
	}
	if req.Action == "remove-cron" {
		if !identifier(stringValue(req.Spec, "cronId")) {
			return "", "", "", errors.New("cron id is invalid")
		}
	}
	if req.Action == "install-ssh-key" {
		parts := strings.Fields(stringValue(req.Spec, "publicKey"))
		if len(parts) < 2 || (parts[0] != "ssh-ed25519" && parts[0] != "ssh-rsa") {
			return "", "", "", errors.New("only ssh-ed25519 or ssh-rsa public keys are accepted")
		}
		if _, err := base64.StdEncoding.DecodeString(parts[1]); err != nil {
			return "", "", "", errors.New("public key payload is not valid base64")
		}
	}
	return root, typeName, stack, nil
}

func atomicWrite(filename, content string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(filename), 0750); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(filename), ".quiet-ops-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(content); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, filename)
}

const olsMainConfig = "/usr/local/lsws/conf/httpd_config.conf"

func reconcileOlsMainConfig(siteID, block string) error {
	if !validSiteID(siteID) {
		return errors.New("invalid site id")
	}
	contents, err := os.ReadFile(olsMainConfig)
	if err != nil {
		return err
	}
	start := "\n# QUIET_OPS_BEGIN " + siteID + "\n"
	end := "\n# QUIET_OPS_END " + siteID + "\n"
	text := string(contents)
	for {
		begin := strings.Index(text, start)
		if begin < 0 {
			break
		}
		remainder := text[begin+len(start):]
		finish := strings.Index(remainder, end)
		if finish < 0 {
			text = text[:begin]
			break
		}
		text = text[:begin] + remainder[finish+len(end):]
	}
	if strings.TrimSpace(block) != "" {
		normalized := strings.TrimSpace(block)
		// OLS's native CCL expects the document root context to use its
		// resolved $DOC_ROOT variable. Keep the generated fragment readable,
		// but normalize the installed copy so a release symlink is served.
		normalized = strings.Replace(normalized, "location /var/lib/quiet-ops/sites/"+siteID+"/current/", "location $DOC_ROOT/", 1)
		if strings.Contains(normalized, "    location $DOC_ROOT/\n") && !strings.Contains(normalized, "accessControl {") {
			normalized = strings.Replace(normalized, "    location $DOC_ROOT/\n", "    location $DOC_ROOT/\n    accessControl {\n      allow *\n    }\n", 1)
		}
		text = strings.TrimRight(text, "\n") + start + normalized + end
	}
	return atomicWrite(olsMainConfig, text+"\n", 0640)
}

func command(ctx context.Context, name string, args ...string) (string, error) {
	executable, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("required executable %q is unavailable", name)
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return message, fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), message)
	}
	return strings.TrimSpace(string(output)), nil
}

func runFixed(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := command(ctx, name, args...)
	return err
}

func commandWithTimeout(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return command(ctx, name, args...)
}

func ensureSiteIdentity(root, siteID string) (string, error) {
	username := safeName(siteID)
	if _, err := user.Lookup(username); err != nil {
		if err := runFixed("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", root, "--shell", "/usr/sbin/nologin", username); err != nil {
			return "", err
		}
	}
	// Site users never join the shared panel group: that would let one
	// workload read another workload's files. The panel owns the qops group
	// on each site directory; the runtime keeps its private primary group.
	return username, nil
}

func applySiteOwnership(root, username string) error {
	siteUser, err := user.Lookup(username)
	if err != nil {
		return err
	}
	panelGroup, err := user.LookupGroup("quiet-ops")
	if err != nil {
		return err
	}
	controlGID := 0
	if controlGroup, controlErr := user.LookupGroup("quiet-ops-control"); controlErr == nil {
		controlGID, _ = strconv.Atoi(controlGroup.Gid)
	}
	uid, err := strconv.Atoi(siteUser.Uid)
	if err != nil {
		return err
	}
	siteGID, err := strconv.Atoi(siteUser.Gid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(panelGroup.Gid)
	if err != nil {
		return err
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	if err := filepath.Walk(root, func(filename string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			realTarget, targetErr := filepath.EvalSymlinks(filename)
			if targetErr != nil || (realTarget != realRoot && !strings.HasPrefix(realTarget, realRoot+string(os.PathSeparator))) {
				return errors.New("site symlink escapes the site root")
			}
		}
		chown := os.Chown
		if info.Mode()&os.ModeSymlink != 0 {
			chown = os.Lchown
		}
		if err := chown(filename, uid, gid); err != nil {
			return err
		}
		relative, relativeErr := filepath.Rel(root, filename)
		privateTree := relativeErr == nil && (relative == "secrets" || strings.HasPrefix(relative, "secrets"+string(os.PathSeparator)) || relative == "backups" || strings.HasPrefix(relative, "backups"+string(os.PathSeparator)))
		if privateTree {
			privateGID := siteGID
			privateUID := uid
			privateDirMode, privateFileMode := os.FileMode(0700), os.FileMode(0600)
			if relative == "backups" || strings.HasPrefix(relative, "backups"+string(os.PathSeparator)) {
				if controlGID == 0 {
					return errors.New("quiet-ops-control group is required for backup access")
				}
				privateGID = controlGID
				// Backups are created/read by the panel and root agent, never by
				// the site runtime identity. Keep the tree root-owned while
				// granting the panel's control group read/traverse access.
				privateUID = 0
				privateDirMode, privateFileMode = 0770, 0640
			}
			if err := chown(filename, privateUID, privateGID); err != nil {
				return err
			}
			if info.IsDir() {
				return os.Chmod(filename, privateDirMode)
			}
			if info.Mode()&os.ModeSymlink == 0 {
				return os.Chmod(filename, privateFileMode)
			}
			return nil
		}
		if info.IsDir() {
			if filepath.Base(filename) == ".ssh" {
				return os.Chmod(filename, 0700)
			}
			return os.Chmod(filename, 0770)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			if filepath.Base(filename) == "authorized_keys" {
				return os.Chmod(filename, 0600)
			}
			return os.Chmod(filename, 0660)
		}
		return nil
	}); err != nil {
		return err
	}
	// The shared web workers must be able to read published releases, but
	// never site secrets, backups, SSH material, or control-plane trees. ACLs
	// avoid putting www-data/nobody in the writable quiet-ops group.
	if _, err := commandWithTimeout("setfacl", "-m", "u:www-data:--x,u:nobody:--x", root); err != nil {
		return err
	}
	publicReleases := filepath.Join(root, "releases")
	if _, err := commandWithTimeout("setfacl", "-R", "-m", "u:www-data:rX,u:nobody:rX", publicReleases); err != nil {
		return err
	}
	return nil
}

func systemdUnit(siteID, username, root, typeName string, spec map[string]any) (string, error) {
	if typeName != "node" && typeName != "next" {
		return "", nil
	}
	entry := stringValue(spec, "entry")
	if entry == "" {
		if typeName == "next" {
			entry = ".next/standalone/server.js"
		} else {
			entry = "server.js"
		}
	}
	if strings.HasPrefix(entry, "/") || strings.Contains(entry, "..") || strings.ContainsAny(entry, " \t\r\n%\\\"';&|$`\x00") {
		return "", errors.New("runtime entry contains unsupported characters")
	}
	entryAbsolute, err := relativeSitePath(root, filepath.Join(root, "current", entry))
	if err != nil {
		return "", fmt.Errorf("invalid runtime entry: %w", err)
	}
	port := stringValue(spec, "port")
	if port == "" {
		port = "3000"
	}
	if len(port) > 5 || strings.Trim(port, "0123456789") != "" {
		return "", errors.New("runtime port must be numeric")
	}
	memoryMb, err := integerValue(spec, "memoryMb", 512, 64, 16384)
	if err != nil {
		return "", err
	}
	cpuPercent, err := integerValue(spec, "cpuPercent", 25, 1, 800)
	if err != nil {
		return "", err
	}
	isolation := stringValue(spec, "isolation")
	if isolation == "" {
		isolation = "process"
	}
	if isolation != "process" && isolation != "docker" {
		return "", errors.New("unsupported runtime isolation")
	}
	image := stringValue(spec, "image")
	if isolation == "docker" {
		if image == "" || !validImage(image) {
			return "", errors.New("a valid Docker image is required for docker isolation")
		}
		siteIdentity, identityErr := user.Lookup(username)
		if identityErr != nil || !numericIdentifier(siteIdentity.Uid) || !numericIdentifier(siteIdentity.Gid) {
			return "", errors.New("site identity is unavailable for Docker runtime")
		}
		entryRelative, _ := filepath.Rel(filepath.Join(root, "current"), entryAbsolute)
		// The unit runs as root only to access /run/docker.sock. The container
		// itself is pinned to the site UID/GID and receives no host socket.
		return fmt.Sprintf(`[Unit]
Description=Quiet Ops site %s Docker runtime
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=%s/current
ExecStart=/usr/bin/docker run --rm --name quiet-ops-%s --user %s:%s --network bridge --publish 127.0.0.1:%s:%s --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --cap-drop ALL --security-opt no-new-privileges=true --pids-limit 128 --memory %dM --cpus %.2f --volume %s/current:/app:ro --workdir /app %s node %s
ExecStop=/usr/bin/docker stop --time 10 quiet-ops-%s
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
MemoryMax=%dM
CPUQuota=%d%%
TasksMax=128
Environment=PORT=%s

[Install]
WantedBy=multi-user.target
		`, siteID, root, siteID, siteIdentity.Uid, siteIdentity.Gid, port, port, memoryMb, float64(cpuPercent)/100.0, root, image, entryRelative, siteID, memoryMb, cpuPercent, port), nil
	}
	return fmt.Sprintf(`[Unit]
Description=Quiet Ops site %s runtime
After=network.target

[Service]
Type=simple
User=%s
Group=%s
WorkingDirectory=%s/current
ExecStart=/usr/bin/node %s
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=%s/current %s/releases
MemoryMax=%dM
CPUQuota=%d%%
TasksMax=128
Environment=PORT=%s

[Install]
WantedBy=multi-user.target
`, siteID, username, username, root, entryAbsolute, root, root, memoryMb, cpuPercent, port), nil
}

func phpFpmPool(siteID, username, root string) (string, error) {
	if siteID == "" || username == "" {
		return "", errors.New("PHP-FPM pool identity is required")
	}
	if _, err := relativeSitePath(root, filepath.Join(root, "current")); err != nil {
		return "", err
	}
	return fmt.Sprintf(`[%s]
user = %s
group = %s
listen = /run/quiet-ops/%s.php.sock
listen.owner = %s
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 4
pm.process_idle_timeout = 10s
pm.max_requests = 200
chdir = %s/current
clear_env = yes
php_admin_value[open_basedir] = %s/current:/tmp
`, safeName(siteID), username, username, siteID, username, root, root), nil
}

func validImage(image string) bool {
	if image == "" || len(image) > 191 || strings.ContainsAny(image, " \t\r\n\x00") {
		return false
	}
	for _, character := range image {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || strings.ContainsRune("./:_@-", character) {
			continue
		}
		return false
	}
	return true
}

func numericIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func certificateDomains(spec map[string]any) ([]string, error) {
	values, ok := spec["domains"].([]any)
	if !ok || len(values) == 0 || len(values) > 20 {
		return nil, errors.New("one to twenty certificate domains are required")
	}
	valid := make([]string, 0, len(values))
	for _, raw := range values {
		domain, ok := raw.(string)
		if !ok || len(domain) > 253 || !validDomain(domain) {
			return nil, errors.New("invalid certificate domain")
		}
		valid = append(valid, domain)
	}
	return valid, nil
}

func validDomain(domain string) bool {
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if len(part) < 1 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, character := range part {
			if !(character == '-' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9') {
				return false
			}
		}
	}
	return true
}

func issueCertificate(req Request, spec map[string]any) (map[string]any, error) {
	domains, err := certificateDomains(spec)
	if err != nil {
		return nil, err
	}
	args := []string{"certonly", "--nginx", "--non-interactive", "--agree-tos", "--register-unsafely-without-email"}
	for _, domain := range domains {
		args = append(args, "-d", domain)
	}
	if _, err := commandWithTimeout("certbot", args...); err != nil {
		return nil, err
	}
	return map[string]any{"mode": "live", "domains": domains, "certificateRoot": "/etc/letsencrypt/live/" + domains[0]}, nil
}

func identifier(value string) bool {
	if len(value) < 1 || len(value) > 48 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return false
	}
	return true
}

func cronExpression(value string) bool {
	fields := strings.Fields(value)
	if len(fields) != 5 {
		return false
	}
	for _, field := range fields {
		if len(field) == 0 || len(field) > 32 || strings.Trim(field, "0123456789*/,-") != "" {
			return false
		}
	}
	return true
}

func cronCommand(value string) ([]string, error) {
	if value == "" || len(value) > 500 || strings.ContainsAny(value, "\r\n;&|$`<>\x00'\"") {
		return nil, errors.New("cron command must be a plain allowlisted argv")
	}
	argv := strings.Fields(value)
	if len(argv) == 0 || len(argv) > 16 {
		return nil, errors.New("cron command must contain one to sixteen arguments")
	}
	allowed := map[string]bool{"wp": true, "php": true, "node": true, "npm": true}
	if !allowed[filepath.Base(argv[0])] {
		return nil, errors.New("cron executable is not allowlisted")
	}
	for _, argument := range argv {
		if len(argument) > 256 || strings.HasPrefix(argument, "/") || strings.Contains(argument, "..") {
			return nil, errors.New("cron argument escapes the site workspace")
		}
	}
	return argv, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func sqlQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }

func commandInput(ctx context.Context, input, name string, args ...string) (string, error) {
	executable, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("required executable %q is unavailable", name)
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return message, fmt.Errorf("%s: %s", name, message)
	}
	return strings.TrimSpace(string(output)), nil
}

func commandInputAsUser(ctx context.Context, username, input, name string, args ...string) (string, error) {
	if !safeScriptName(username) {
		return "", errors.New("service account name is invalid")
	}
	executable, err := exec.LookPath("runuser")
	if err != nil {
		return "", fmt.Errorf("required executable %q is unavailable", "runuser")
	}
	commandArgs := append([]string{"-u", username, "--", name}, args...)
	cmd := exec.CommandContext(ctx, executable, commandArgs...)
	cmd.Stdin = strings.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return message, fmt.Errorf("%s: %s", name, message)
	}
	return strings.TrimSpace(string(output)), nil
}

func commandEnv(ctx context.Context, environment []string, name string, args ...string) (string, error) {
	executable, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("required executable %q is unavailable", name)
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = append(os.Environ(), environment...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return message, fmt.Errorf("%s: %s", name, message)
	}
	return strings.TrimSpace(string(output)), nil
}

func commandAsSite(ctx context.Context, root, siteID string, environment []string, name string, args ...string) (string, error) {
	username, err := ensureSiteIdentity(root, siteID)
	if err != nil {
		return "", err
	}
	siteUser, err := user.Lookup(username)
	if err != nil {
		return "", err
	}
	uid, err := strconv.Atoi(siteUser.Uid)
	if err != nil {
		return "", err
	}
	gid, err := strconv.Atoi(siteUser.Gid)
	if err != nil {
		return "", err
	}
	executable, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("required executable %q is unavailable", name)
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = append([]string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + root,
		"TMPDIR=/tmp",
		"GIT_TERMINAL_PROMPT=0",
	}, environment...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}}
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return message, fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), message)
	}
	return strings.TrimSpace(string(output)), nil
}

// dockerAsSite keeps Docker's privileged socket inside the root agent. The
// process in the container is still pinned to the site's numeric UID/GID and
// receives no socket, host network, extra capabilities, or ambient secrets.
func dockerAsSite(ctx context.Context, root, siteID, mountPath, image string, commandArgs ...string) (string, error) {
	username, err := ensureSiteIdentity(root, siteID)
	if err != nil {
		return "", err
	}
	siteUser, err := user.Lookup(username)
	if err != nil || !numericIdentifier(siteUser.Uid) || !numericIdentifier(siteUser.Gid) {
		return "", errors.New("site identity is unavailable for Docker execution")
	}
	executable, err := exec.LookPath("docker")
	if err != nil {
		return "", fmt.Errorf("required executable %q is unavailable", "docker")
	}
	args := []string{"run", "--rm", "--user", siteUser.Uid + ":" + siteUser.Gid, "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m", "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--pids-limit", "128", "--memory", "512m", "--cpus", "1", "--volume", mountPath + ":/app:rw", "--workdir", "/app", image}
	args = append(args, commandArgs...)
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/app", "DOCKER_CONFIG=/dev/null"}
	output, err := cmd.CombinedOutput()
	if len(output) > 128*1024 {
		output = output[:128*1024]
	}
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return message, fmt.Errorf("docker build command failed: %s", message)
	}
	return strings.TrimSpace(string(output)), nil
}

func commandBytesEnv(ctx context.Context, environment []string, name string, args ...string) ([]byte, error) {
	executable, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("required executable %q is unavailable", name)
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = append(os.Environ(), environment...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return nil, fmt.Errorf("%s: %s", name, message)
	}
	return output, nil
}

func commandToFile(ctx context.Context, filename, name string, environment []string, args ...string) error {
	executable, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("required executable %q is unavailable", name)
	}
	outputFile, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer outputFile.Close()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdout = outputFile
	cmd.Stderr = outputFile
	cmd.Env = append(os.Environ(), environment...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

func commandFromFile(ctx context.Context, filename, name string, environment []string, args ...string) error {
	executable, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("required executable %q is unavailable", name)
	}
	input, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer input.Close()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdin = input
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	cmd.Env = append(os.Environ(), environment...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

func randomPassword() (string, error) {
	bytes := make([]byte, 24)
	if _, err := crand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("q%x", bytes), nil
}

func provisionDataService(req Request, cfg Config, root string, spec map[string]any) (map[string]any, error) {
	engine := stringValue(spec, "engine")
	if engine != "mariadb" && engine != "postgresql" && engine != "redis" {
		return nil, errors.New("unsupported data-service engine")
	}
	database := stringValue(spec, "database")
	username := stringValue(spec, "username")
	if !identifier(database) || !identifier(username) {
		return nil, errors.New("database and username must be safe identifiers")
	}
	password, err := randomPassword()
	if err != nil {
		return nil, err
	}
	secretDir := filepath.Join(root, "secrets")
	secretFile := filepath.Join(secretDir, engine+".env")
	secret := fmt.Sprintf("ENGINE=%s\nDATABASE=%s\nUSERNAME=%s\nPASSWORD=%s\n", engine, database, username, password)
	if err := atomicWrite(secretFile, secret, 0640); err != nil {
		return nil, err
	}
	siteUser, err := ensureSiteIdentity(root, req.SiteID)
	if err != nil {
		return nil, err
	}
	if err := applySiteOwnership(root, siteUser); err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(secretFile)
		}
	}()
	if err := ensureDataService(engine); err != nil {
		return nil, err
	}
	var input string
	switch engine {
	case "mariadb":
		input = fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`; CREATE USER IF NOT EXISTS %s@'localhost' IDENTIFIED BY %s; GRANT ALL PRIVILEGES ON `%s`.* TO %s@'localhost'; FLUSH PRIVILEGES;\n", database, sqlQuote(username), sqlQuote(password), database, sqlQuote(username))
	case "postgresql":
		input = fmt.Sprintf("DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = %s) THEN CREATE ROLE \"%s\" LOGIN PASSWORD %s; END IF; END $$; SELECT 'CREATE DATABASE \"%s\" OWNER \"%s\"' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = %s)\\gexec GRANT ALL PRIVILEGES ON DATABASE \"%s\" TO \"%s\";\n", sqlQuote(username), username, sqlQuote(password), database, username, sqlQuote(database), database, username)
	case "redis":
		input = ""
	}
	if engine == "mariadb" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if _, err := commandInput(ctx, input, "mariadb", "--protocol=socket", "--batch", "--skip-column-names"); err != nil {
			return nil, err
		}
	}
	if engine == "postgresql" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if _, err := commandInputAsUser(ctx, "postgres", input, "psql", "--dbname=postgres", "--set=ON_ERROR_STOP=1"); err != nil {
			return nil, err
		}
	}
	if engine == "redis" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if _, err := commandInput(ctx, fmt.Sprintf("ACL SETUSER %s on >%s ~%s:* +@all\n", username, password, username), "redis-cli"); err != nil {
			return nil, errors.New("redis ACL setup failed")
		}
	}
	committed = true
	return map[string]any{"mode": "live", "engine": engine, "database": database, "username": username, "credentialFile": secretFile, "secret": "omitted"}, nil
}

func secretValues(filename string) (map[string]string, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(contents), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			values[parts[0]] = parts[1]
		}
	}
	return values, nil
}

type redisDumpEntry struct {
	Key     string `json:"key"`
	TTL     int64  `json:"ttl"`
	Payload string `json:"payload"`
}

func backupRedis(ctx context.Context, outputPath, username, password string) error {
	scanOutput, err := commandEnv(ctx, []string{"REDISCLI_AUTH=" + password}, "redis-cli", "--user", username, "--scan")
	if err != nil {
		return err
	}
	keys := strings.Split(strings.TrimSpace(scanOutput), "\n")
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer output.Close()
	encoder := json.NewEncoder(output)
	var total int64
	count := 0
	for _, key := range keys {
		key = strings.TrimSuffix(key, "\r")
		if key == "" {
			continue
		}
		if !strings.HasPrefix(key, username+":") {
			return fmt.Errorf("Redis key is outside the site namespace")
		}
		if count >= 10000 {
			return errors.New("Redis backup exceeds the 10000-key safety limit")
		}
		payload, dumpErr := commandBytesEnv(ctx, []string{"REDISCLI_AUTH=" + password}, "redis-cli", "--user", username, "--raw", "DUMP", key)
		if dumpErr != nil {
			return dumpErr
		}
		if string(payload) == "(nil)\n" {
			continue
		}
		if len(payload) > 0 && payload[len(payload)-1] == '\n' {
			payload = payload[:len(payload)-1]
		}
		if len(payload) == 0 {
			continue
		}
		ttlText, ttlErr := commandEnv(ctx, []string{"REDISCLI_AUTH=" + password}, "redis-cli", "--user", username, "PTTL", key)
		if ttlErr != nil {
			return ttlErr
		}
		ttl, parseErr := strconv.ParseInt(strings.TrimSpace(ttlText), 10, 64)
		if parseErr != nil {
			return fmt.Errorf("Redis key TTL is invalid")
		}
		if ttl < 0 {
			ttl = 0
		}
		entry := redisDumpEntry{Key: key, TTL: ttl, Payload: base64.StdEncoding.EncodeToString(payload)}
		if err := encoder.Encode(entry); err != nil {
			return err
		}
		total += int64(len(key) + len(payload))
		if total > 256*1024*1024 {
			return errors.New("Redis backup exceeds the 256 MiB safety limit")
		}
		count++
	}
	return nil
}

func writeRESP(writer io.Writer, values ...[]byte) error {
	if _, err := fmt.Fprintf(writer, "*%d\r\n", len(values)); err != nil {
		return err
	}
	for _, value := range values {
		if _, err := fmt.Fprintf(writer, "$%d\r\n", len(value)); err != nil {
			return err
		}
		if _, err := writer.Write(value); err != nil {
			return err
		}
		if _, err := io.WriteString(writer, "\r\n"); err != nil {
			return err
		}
	}
	return nil
}

func restoreRedis(inputPath, username, password string) error {
	executable, err := exec.LookPath("redis-cli")
	if err != nil {
		return err
	}
	input, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer input.Close()
	cmd := exec.Command(executable, "--user", username, "--pipe")
	cmd.Env = append(os.Environ(), "REDISCLI_AUTH="+password)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 8*1024*1024)
	count := 0
	var total int64
	for scanner.Scan() {
		var entry redisDumpEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			return errors.New("Redis backup entry is invalid")
		}
		if !strings.HasPrefix(entry.Key, username+":") || entry.TTL < 0 || count >= 10000 {
			_ = stdin.Close()
			_ = cmd.Wait()
			return errors.New("Redis backup entry is outside the supported namespace")
		}
		payload, err := base64.StdEncoding.DecodeString(entry.Payload)
		if err != nil || len(payload) == 0 {
			_ = stdin.Close()
			_ = cmd.Wait()
			return errors.New("Redis backup payload is invalid")
		}
		if err := writeRESP(stdin, []byte("RESTORE"), []byte(entry.Key), []byte(strconv.FormatInt(entry.TTL, 10)), payload, []byte("REPLACE")); err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			return err
		}
		total += int64(len(entry.Key) + len(payload))
		if total > 256*1024*1024 {
			_ = stdin.Close()
			_ = cmd.Wait()
			return errors.New("Redis restore exceeds the 256 MiB safety limit")
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		_ = stdin.Close()
		_ = cmd.Wait()
		return err
	}
	if err := stdin.Close(); err != nil {
		_ = cmd.Wait()
		return err
	}
	return cmd.Wait()
}

func backupDataService(req Request, root string, spec map[string]any) (map[string]any, error) {
	engine := stringValue(spec, "engine")
	database := stringValue(spec, "database")
	username := stringValue(spec, "username")
	if (engine != "mariadb" && engine != "postgresql" && engine != "redis") || !identifier(database) || !identifier(username) {
		return nil, errors.New("invalid data-service backup specification")
	}
	outputPath, err := relativeSitePath(root, stringValue(spec, "outputPath"))
	if err != nil {
		return nil, err
	}
	values, err := secretValues(filepath.Join(root, "secrets", engine+".env"))
	if err != nil {
		return nil, errors.New("site data-service credential file is unavailable")
	}
	password := values["PASSWORD"]
	if password == "" {
		return nil, errors.New("site data-service password is unavailable")
	}
	if err := ensureDataService(engine); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0770); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	switch engine {
	case "mariadb":
		err = commandToFile(ctx, outputPath, "mariadb-dump", []string{"MYSQL_PWD=" + password}, "--protocol=socket", "--user="+username, "--single-transaction", "--routines", "--events", database)
	case "postgresql":
		err = commandToFile(ctx, outputPath, "pg_dump", []string{"PGPASSWORD=" + password}, "--host=127.0.0.1", "--format=plain", "--no-owner", "--username="+username, "--dbname="+database)
	case "redis":
		err = backupRedis(ctx, outputPath, username, password)
	}
	if err != nil {
		_ = os.Remove(outputPath)
		return nil, err
	}
	siteUser, err := ensureSiteIdentity(root, req.SiteID)
	if err != nil {
		_ = os.Remove(outputPath)
		return nil, err
	}
	if err := applySiteOwnership(root, siteUser); err != nil {
		_ = os.Remove(outputPath)
		return nil, err
	}
	return map[string]any{"mode": "live", "engine": engine, "database": database, "dumpPath": outputPath, "encryptedByPanel": true, "secret": "omitted"}, nil
}

func restoreDataService(req Request, root string, spec map[string]any) (map[string]any, error) {
	engine := stringValue(spec, "engine")
	database := stringValue(spec, "database")
	username := stringValue(spec, "username")
	if (engine != "mariadb" && engine != "postgresql" && engine != "redis") || !identifier(database) || !identifier(username) {
		return nil, errors.New("invalid data-service restore specification")
	}
	inputPath, err := relativeSitePath(root, stringValue(spec, "inputPath"))
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(inputPath)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("data-service restore dump is unavailable")
	}
	if info.Size() > 256*1024*1024 {
		return nil, errors.New("data-service restore dump exceeds the 256 MiB safety limit")
	}
	values, err := secretValues(filepath.Join(root, "secrets", engine+".env"))
	if err != nil || values["PASSWORD"] == "" {
		return nil, errors.New("site data-service credential file is unavailable")
	}
	if err := ensureDataService(engine); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if engine == "mariadb" {
		err = commandFromFile(ctx, inputPath, "mariadb", []string{"MYSQL_PWD=" + values["PASSWORD"]}, "--protocol=socket", "--user="+username, database)
	} else if engine == "postgresql" {
		err = commandFromFile(ctx, inputPath, "psql", []string{"PGPASSWORD=" + values["PASSWORD"]}, "--host=127.0.0.1", "--set=ON_ERROR_STOP=1", "--username="+username, "--dbname="+database)
	} else {
		err = restoreRedis(inputPath, username, values["PASSWORD"])
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"mode": "live", "engine": engine, "database": database, "restoredFrom": inputPath, "secret": "omitted"}, nil
}

func deprovisionDataService(engine, database, username string) (map[string]any, error) {
	if !identifier(database) || !identifier(username) {
		return nil, errors.New("database and username must be safe identifiers")
	}
	if err := ensureDataService(engine); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch engine {
	case "mariadb":
		input := fmt.Sprintf("DROP DATABASE IF EXISTS `%s`; DROP USER IF EXISTS %s@'localhost'; FLUSH PRIVILEGES;\n", database, sqlQuote(username))
		if _, err := commandInput(ctx, input, "mariadb", "--protocol=socket", "--batch", "--skip-column-names"); err != nil {
			return nil, err
		}
	case "postgresql":
		input := fmt.Sprintf("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=%s; DROP DATABASE IF EXISTS \"%s\"; DROP ROLE IF EXISTS \"%s\";\n", sqlQuote(database), database, username)
		if _, err := commandInputAsUser(ctx, "postgres", input, "psql", "--dbname=postgres", "--set=ON_ERROR_STOP=1"); err != nil {
			return nil, err
		}
	case "redis":
		keys, err := commandWithTimeout("redis-cli", "--scan", "--pattern", username+":*")
		if err != nil {
			return nil, err
		}
		for _, key := range strings.Split(strings.TrimSpace(keys), "\n") {
			if key == "" {
				continue
			}
			if _, err := commandWithTimeout("redis-cli", "UNLINK", key); err != nil {
				return nil, err
			}
		}
		if _, err := commandInput(ctx, "ACL DELUSER "+username+"\n", "redis-cli"); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported data-service engine")
	}
	return map[string]any{"mode": "live", "engine": engine, "database": database, "username": username, "removed": true}, nil
}

func prepareRelease(req Request, root string, spec map[string]any) (map[string]any, error) {
	repository := stringValue(spec, "repo")
	if !strings.HasPrefix(repository, "https://") || strings.ContainsAny(repository, " \t\r\n\x00") {
		return nil, errors.New("live Git deployments require an HTTPS repository URL")
	}
	parsed, parseErr := url.Parse(repository)
	if parseErr != nil || parsed.User != nil {
		return nil, errors.New("Git credentials must use the protected credential store")
	}
	releasePath, err := relativeSitePath(root, stringValue(spec, "releasePath"))
	if err != nil {
		return nil, err
	}
	branch := stringValue(spec, "branch")
	if branch == "" {
		branch = "main"
	}
	if len(branch) > 120 || strings.ContainsAny(branch, " \t\r\n\x00") {
		return nil, errors.New("Git branch is invalid")
	}
	if err := os.MkdirAll(filepath.Dir(releasePath), 0770); err != nil {
		return nil, err
	}
	if entries, err := os.ReadDir(releasePath); err == nil && len(entries) > 0 {
		return nil, errors.New("release staging directory must be empty")
	}
	credentialKind := stringValue(spec, "credentialKind")
	credentialSecret := stringValue(spec, "credentialSecret")
	if credentialKind != "" && credentialKind != "https-token" {
		return nil, errors.New("unsupported Git credential kind")
	}
	if credentialSecret != "" && (len(credentialSecret) > 4096 || strings.ContainsAny(credentialSecret, "\r\n\x00")) {
		return nil, errors.New("Git credential value is invalid")
	}
	username, err := ensureSiteIdentity(root, req.SiteID)
	if err != nil {
		return nil, err
	}
	if err := applySiteOwnership(root, username); err != nil {
		return nil, err
	}
	cloneArgs := []string{"clone", "--depth", "1", "--branch", branch, repository, releasePath}
	var cloneErr error
	if credentialSecret != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_, cloneErr = commandAsSite(ctx, root, req.SiteID, []string{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: Bearer " + credentialSecret}, "git", cloneArgs...)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_, cloneErr = commandAsSite(ctx, root, req.SiteID, nil, "git", cloneArgs...)
	}
	if cloneErr != nil {
		return nil, cloneErr
	}
	typeName := stringValue(spec, "type")
	build := stringValue(spec, "build")
	if build == "" {
		build = "none"
	}
	if build != "none" && build != "node" && build != "next" {
		return nil, errors.New("unsupported build profile")
	}
	if build != "none" {
		image := stringValue(spec, "image")
		if image == "" || !validImage(image) {
			return nil, errors.New("Node/Next Git builds require a validated Docker image")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		if _, err := dockerAsSite(ctx, root, req.SiteID, releasePath, image, "npm", "ci"); err != nil {
			cancel()
			return nil, err
		}
		if _, err := dockerAsSite(ctx, root, req.SiteID, releasePath, image, "npm", "run", "build"); err != nil {
			cancel()
			return nil, err
		}
		cancel()
	}
	return map[string]any{"mode": "live", "repo": repository, "branch": branch, "releasePath": releasePath, "type": typeName, "build": build, "credentials": "host-managed-git-transport"}, nil
}

func workspaceCommand(spec map[string]any) ([]string, error) {
	raw, ok := spec["argv"].([]any)
	if !ok || len(raw) == 0 || len(raw) > 16 {
		return nil, errors.New("workspace argv must contain one to sixteen arguments")
	}
	argv := make([]string, len(raw))
	for index, value := range raw {
		argument, ok := value.(string)
		if !ok || argument == "" || len(argument) > 512 || strings.ContainsAny(argument, "\x00\r\n") {
			return nil, errors.New("workspace argument is invalid")
		}
		argv[index] = argument
	}
	allowed := map[string]bool{"pwd": true, "ls": true, "cat": true, "head": true, "tail": true, "git": true, "node": true, "npm": true, "php": true, "wp": true}
	if !allowed[filepath.Base(argv[0])] {
		return nil, errors.New("workspace command is not allowlisted")
	}
	commandName := filepath.Base(argv[0])
	if commandName == "pwd" && len(argv) != 1 {
		return nil, errors.New("pwd takes no arguments")
	}
	for _, argument := range argv[1:] {
		if strings.HasPrefix(argument, "/") || strings.Contains(argument, "..") || strings.ContainsAny(argument, ";&|$`<>\x00") {
			return nil, errors.New("workspace path or operator escapes the site")
		}
	}
	if commandName == "git" {
		if len(argv) < 2 || !map[string]bool{"status": true, "log": true, "diff": true}[argv[1]] {
			return nil, errors.New("only read-only git status, log, and diff are allowed")
		}
	}
	if commandName == "npm" {
		if len(argv) < 2 || !map[string]bool{"ci": true, "run": true, "start": true, "test": true}[argv[1]] {
			return nil, errors.New("npm workspace action is not allowlisted")
		}
		if argv[1] == "run" && (len(argv) != 3 || !safeScriptName(argv[2])) {
			return nil, errors.New("npm run requires one safe script name")
		}
	}
	if commandName == "node" && (len(argv) != 2 || !safeWorkspacePath(argv[1])) {
		return nil, errors.New("node requires one site-relative script")
	}
	return argv, nil
}

func safeWorkspacePath(value string) bool {
	return value != "" && !strings.HasPrefix(value, "/") && !strings.Contains(value, "..") && !strings.ContainsAny(value, ";&|$`<>\x00")
}
func safeScriptName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !(character == '-' || character == '_' || character == ':' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func runWorkspace(req Request, root string, spec map[string]any) (map[string]any, error) {
	argv, err := workspaceCommand(spec)
	if err != nil {
		return nil, err
	}
	username, err := ensureSiteIdentity(root, req.SiteID)
	if err != nil {
		return nil, err
	}
	siteUser, err := user.Lookup(username)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(siteUser.Uid)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(siteUser.Gid)
	if err != nil {
		return nil, err
	}
	working := filepath.Join(root, "current")
	if _, err := os.Stat(working); err != nil {
		working = root
	}
	executable, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, argv[1:]...)
	cmd.Dir = working
	// Do not inherit the agent's environment into an AI workspace. The
	// workspace is intentionally secretless and receives only safe basics.
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + working,
		"TMPDIR=/tmp",
		"GIT_TERMINAL_PROMPT=0",
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{uint32(gid)}}}
	output, err := cmd.CombinedOutput()
	if len(output) > 64*1024 {
		output = output[:64*1024]
	}
	if err != nil {
		return map[string]any{"mode": "live", "argv": argv, "output": string(output)}, fmt.Errorf("workspace command failed: %w", err)
	}
	return map[string]any{"mode": "live", "argv": argv, "output": string(output), "siteUser": username}, nil
}

func installSshKey(req Request, root string, spec map[string]any) (map[string]any, error) {
	publicKey := strings.TrimSpace(stringValue(spec, "publicKey"))
	parts := strings.Fields(publicKey)
	if len(parts) < 2 || (parts[0] != "ssh-ed25519" && parts[0] != "ssh-rsa") || strings.ContainsAny(publicKey, "\r\n\x00") {
		return nil, errors.New("only ssh-ed25519 or ssh-rsa public keys are accepted")
	}
	if _, err := base64.StdEncoding.DecodeString(parts[1]); err != nil {
		return nil, errors.New("public key payload is not valid base64")
	}
	username, err := ensureSiteIdentity(root, req.SiteID)
	if err != nil {
		return nil, err
	}
	authorized := filepath.Join(root, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(authorized), 0700); err != nil {
		return nil, err
	}
	existing, _ := os.ReadFile(authorized)
	line := "restrict,command=\"internal-sftp -d current\" " + publicKey + "\n"
	if !strings.Contains(string(existing), publicKey) {
		if err := os.WriteFile(authorized, append(existing, []byte(line)...), 0600); err != nil {
			return nil, err
		}
	}
	if err := applySiteOwnership(root, username); err != nil {
		return nil, err
	}
	if err := os.Chmod(authorized, 0600); err != nil {
		return nil, err
	}
	return map[string]any{"mode": "live", "siteUser": username, "authorizedKeys": authorized, "transport": "SFTP-only forced command", "privateKey": "never accepted"}, nil
}

func installCron(req Request, cfg Config, root string, spec map[string]any) (map[string]any, error) {
	cronID := stringValue(spec, "cronId")
	if !identifier(cronID) || !cronExpression(stringValue(spec, "expression")) {
		return nil, errors.New("cron id or expression is invalid")
	}
	argv, err := cronCommand(stringValue(spec, "command"))
	if err != nil {
		return nil, err
	}
	username, err := ensureSiteIdentity(root, req.SiteID)
	if err != nil {
		return nil, err
	}
	executable, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, err
	}
	lockDir := filepath.Join(root, "locks")
	if err := os.MkdirAll(lockDir, 0770); err != nil {
		return nil, err
	}
	scriptPath := filepath.Join(root, "cron", cronID+".sh")
	lockPath := filepath.Join(lockDir, cronID+".lock")
	commandParts := []string{shellQuote(executable)}
	for _, argument := range argv[1:] {
		commandParts = append(commandParts, shellQuote(argument))
	}
	script := fmt.Sprintf("#!/bin/sh\nset -eu\ncd %s/current\nexec /usr/bin/flock -n %s /usr/bin/timeout 300s %s\n", shellQuote(root), shellQuote(lockPath), strings.Join(commandParts, " "))
	if err := atomicWrite(scriptPath, script, 0750); err != nil {
		return nil, err
	}
	if err := applySiteOwnership(root, username); err != nil {
		return nil, err
	}
	if err := os.Chmod(scriptPath, 0750); err != nil {
		return nil, err
	}
	if cfg.CronRoot == "" {
		return nil, errors.New("cron directory is not configured")
	}
	cronFile := filepath.Join(cfg.CronRoot, "quiet-ops-"+req.SiteID+"-"+cronID)
	entry := fmt.Sprintf("# Quiet Ops site %s\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n%s %s %s\n", req.SiteID, stringValue(spec, "expression"), username, scriptPath)
	if err := atomicWrite(cronFile, entry, 0644); err != nil {
		return nil, err
	}
	return map[string]any{"mode": "live", "cronId": cronID, "cronFile": cronFile, "script": scriptPath, "siteUser": username, "overlap": "flock-n", "timeoutSeconds": 300}, nil
}

func removeCron(req Request, cfg Config, root string, spec map[string]any) (map[string]any, error) {
	cronID := stringValue(spec, "cronId")
	if !identifier(cronID) {
		return nil, errors.New("cron id is invalid")
	}
	if cfg.CronRoot != "" {
		_ = os.Remove(filepath.Join(cfg.CronRoot, "quiet-ops-"+req.SiteID+"-"+cronID))
	}
	_ = os.Remove(filepath.Join(root, "cron", cronID+".sh"))
	return map[string]any{"mode": "live", "cronId": cronID, "removed": true}, nil
}

func converge(req Request, cfg Config, root, typeName, stack string) (map[string]any, error) {
	if err := os.MkdirAll(filepath.Join(root, "releases"), 0750); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, "current"), 0750); err != nil {
		return nil, err
	}
	username, err := ensureSiteIdentity(root, req.SiteID)
	if err != nil {
		return nil, err
	}
	if err := applySiteOwnership(root, username); err != nil {
		return nil, err
	}
	runtimeDirectory := ""
	nginxConfig, err := boundedText(stringValue(req.Spec, "nginxConfig"), 512*1024, "nginx config")
	if err != nil {
		return nil, err
	}
	olsConfig, err := boundedText(stringValue(req.Spec, "olsConfig"), 512*1024, "ols config")
	if err != nil {
		return nil, err
	}
	nginxFile := filepath.Join(cfg.NginxConfigRoot, "quiet-ops-"+req.SiteID+".conf")
	if nginxConfig != "" {
		if err := atomicWrite(nginxFile, nginxConfig, 0640); err != nil {
			return nil, err
		}
	}
	olsFile := ""
	if stack == "ols" && olsConfig != "" {
		olsFile = filepath.Join(cfg.OlsConfigRoot, "quiet-ops-"+req.SiteID+".conf")
		if err := atomicWrite(olsFile, olsConfig, 0640); err != nil {
			return nil, err
		}
		if err := reconcileOlsMainConfig(req.SiteID, olsConfig); err != nil {
			return nil, err
		}
	} else {
		// A stack switch away from OLS must remove the old vhost and listener
		// before the next reload, otherwise both edges can continue serving traffic.
		_ = os.Remove(filepath.Join(cfg.OlsConfigRoot, "quiet-ops-"+req.SiteID+".conf"))
		if err := reconcileOlsMainConfig(req.SiteID, ""); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	phpPoolFile := ""
	if typeName == "wordpress" && stack == "nginx" {
		pool, poolErr := phpFpmPool(req.SiteID, username, root)
		if poolErr != nil {
			return nil, poolErr
		}
		phpPoolFile = filepath.Join(cfg.PhpFpmPoolRoot, "quiet-ops-"+req.SiteID+".conf")
		if err := atomicWrite(phpPoolFile, pool, 0640); err != nil {
			return nil, err
		}
	} else {
		_ = os.Remove(filepath.Join(cfg.PhpFpmPoolRoot, "quiet-ops-"+req.SiteID+".conf"))
	}
	unit, err := systemdUnit(req.SiteID, username, root, typeName, req.Spec)
	if err != nil {
		return nil, err
	}
	unitFile := ""
	if unit != "" {
		unitFile = filepath.Join(cfg.UnitRoot, "quiet-ops-site-"+req.SiteID+".service")
		if err := atomicWrite(unitFile, unit, 0644); err != nil {
			return nil, err
		}
		if err := runFixed("systemctl", "daemon-reload"); err != nil {
			return nil, err
		}
		if err := runFixed("systemctl", "enable", "quiet-ops-site-"+req.SiteID+".service"); err != nil {
			return nil, err
		}
	}
	if nginxConfig != "" {
		if _, err := commandWithTimeout("nginx", "-t"); err != nil {
			return nil, err
		}
		if err := runFixed("systemctl", "reload", "nginx"); err != nil {
			return nil, err
		}
	}
	if phpPoolFile != "" {
		if _, err := commandWithTimeout("php-fpm8.3", "-t"); err != nil {
			return nil, err
		}
		if err := runFixed("systemctl", "reload", "php8.3-fpm"); err != nil {
			return nil, err
		}
	}
	if stack == "ols" && olsConfig != "" {
		if _, err := commandWithTimeout("/usr/local/lsws/bin/openlitespeed", "-t"); err != nil {
			return nil, err
		}
		if err := runFixed("systemctl", "reload", "lsws"); err != nil {
			return nil, err
		}
	}
	return map[string]any{"mode": "live", "sitePath": root, "siteUser": username, "nginxConfig": nginxFile, "olsConfig": olsFile, "phpFpmPool": phpPoolFile, "runtimeUnit": unitFile, "runtimeDirectory": runtimeDirectory, "type": typeName, "stack": stack}, nil
}

func publishRelease(req Request, root string) (map[string]any, error) {
	releasePath, err := relativeSitePath(root, stringValue(req.Spec, "releasePath"))
	if err != nil {
		return nil, err
	}
	currentPath := filepath.Join(root, "current")
	if _, err := os.Stat(releasePath); err != nil {
		return nil, fmt.Errorf("release does not exist: %w", err)
	}
	// Manual artifacts are staged by the panel account. Normalize the entire
	// site tree before activation so PHP/Node runtimes can read the release
	// without joining the shared quiet-ops group.
	if os.Geteuid() == 0 {
		username, identityErr := ensureSiteIdentity(root, req.SiteID)
		if identityErr != nil {
			return nil, identityErr
		}
		if ownershipErr := applySiteOwnership(root, username); ownershipErr != nil {
			return nil, ownershipErr
		}
	}
	temporary := filepath.Join(root, ".current-"+req.SiteID+".next")
	previous := filepath.Join(root, ".current-"+req.SiteID+".previous")
	_ = os.Remove(temporary)
	_ = os.Remove(previous)
	if err := os.Symlink(releasePath, temporary); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(currentPath); err == nil {
		if err := os.Rename(currentPath, previous); err != nil {
			_ = os.Remove(temporary)
			return nil, err
		}
	}
	if err := os.Rename(temporary, currentPath); err != nil {
		_ = os.Remove(temporary)
		_ = os.Rename(previous, currentPath)
		return nil, err
	}
	if err := os.RemoveAll(previous); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(currentPath); err != nil {
		_ = os.Remove(temporary)
		return nil, fmt.Errorf("current release was not published: %w", err)
	}
	return map[string]any{"mode": "live", "releasePath": releasePath, "currentPath": currentPath}, nil
}

func deprovision(req Request, cfg Config) (map[string]any, error) {
	root, err := sitePath(cfg.SiteRoot, req.SiteID)
	if err != nil {
		return nil, err
	}
	unitName := "quiet-ops-site-" + req.SiteID + ".service"
	_ = runFixed("systemctl", "stop", unitName)
	_ = runFixed("systemctl", "disable", unitName)
	_ = os.Remove(filepath.Join(cfg.UnitRoot, unitName))
	_ = os.Remove(filepath.Join(cfg.NginxConfigRoot, "quiet-ops-"+req.SiteID+".conf"))
	_ = os.Remove(filepath.Join(cfg.OlsConfigRoot, "quiet-ops-"+req.SiteID+".conf"))
	if err := reconcileOlsMainConfig(req.SiteID, ""); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	_ = os.Remove(filepath.Join(cfg.PhpFpmPoolRoot, "quiet-ops-"+req.SiteID+".conf"))
	// Docker owns container runtime state; stopping/removing the typed unit is
	// the cleanup boundary and no Docker socket is exposed to site users.
	if cfg.CronRoot != "" {
		if cronFiles, globErr := filepath.Glob(filepath.Join(cfg.CronRoot, "quiet-ops-"+req.SiteID+"-cron_*")); globErr == nil {
			for _, filename := range cronFiles {
				_ = os.Remove(filename)
			}
		}
	}
	if os.Geteuid() == 0 {
		username := safeName(req.SiteID)
		if _, lookupErr := user.Lookup(username); lookupErr == nil {
			if err := runFixed("userdel", "--remove", username); err != nil {
				return nil, fmt.Errorf("remove site identity %s: %w", username, err)
			}
		}
	}
	if err := runFixed("systemctl", "daemon-reload"); err != nil {
		return nil, err
	}
	if _, err := commandWithTimeout("nginx", "-t"); err != nil {
		return nil, err
	}
	if err := runFixed("systemctl", "reload", "nginx"); err != nil {
		return nil, err
	}
	if stringValue(req.Spec, "type") == "wordpress" && stringValue(req.Spec, "stack") == "nginx" {
		if _, err := commandWithTimeout("php-fpm8.3", "-t"); err != nil {
			return nil, err
		}
		if err := runFixed("systemctl", "reload", "php8.3-fpm"); err != nil {
			return nil, err
		}
	}
	if stringValue(req.Spec, "stack") == "ols" {
		if _, err := commandWithTimeout("/usr/local/lsws/bin/openlitespeed", "-t"); err != nil {
			return nil, err
		}
		if err := runFixed("systemctl", "reload", "lsws"); err != nil {
			return nil, err
		}
	}
	// The panel has already removed typed data services and required exact
	// deletion confirmation. Remove the workspace here as root so failed or
	// partially provisioned releases owned by the site UID cannot strand the
	// destructive lifecycle job behind filesystem permissions.
	if err := os.RemoveAll(root); err != nil {
		return nil, fmt.Errorf("remove site workspace: %w", err)
	}
	return map[string]any{"mode": "live", "sitePath": root, "removed": true}, nil
}

func serviceAction(req Request, action string) (map[string]any, error) {
	unit := "quiet-ops-site-" + req.SiteID + ".service"
	if err := runFixed("systemctl", action, unit); err != nil {
		return nil, err
	}
	return map[string]any{"mode": "live", "unit": unit, "action": action}, nil
}

func ensureDataService(engine string) error {
	service := map[string]string{"mariadb": "mariadb", "postgresql": "postgresql", "redis": "redis-server"}[engine]
	if service == "" {
		return errors.New("unsupported data-service engine")
	}
	return runFixed("systemctl", "start", service)
}

func directoryExists(filename string) bool {
	info, err := os.Stat(filename)
	return err == nil && info.IsDir()
}

func handle(req Request, cfg Config) Response {
	if !allowedActions[req.Action] {
		return Response{Error: "operation is not allowlisted", DryRun: !cfg.Live}
	}
	root, typeName, stack, err := validateRequest(req, cfg)
	if err != nil {
		return Response{Action: req.Action, SiteID: req.SiteID, Error: err.Error(), DryRun: !cfg.Live}
	}
	if !cfg.Live || req.Action == "preview" {
		return Response{OK: true, Action: req.Action, SiteID: req.SiteID, DryRun: true, Observed: map[string]any{"sitePath": root, "mode": "safe-dry-run", "type": typeName, "stack": stack, "message": "validated; live writes and service commands are disabled"}}
	}
	var observed map[string]any
	switch req.Action {
	case "converge":
		observed, err = converge(req, cfg, root, typeName, stack)
	case "publish-release":
		observed, err = publishRelease(req, root)
	case "deprovision":
		observed, err = deprovision(req, cfg)
	case "start-runtime":
		observed, err = serviceAction(req, "start")
	case "stop-runtime":
		observed, err = serviceAction(req, "stop")
	case "restart-runtime":
		observed, err = serviceAction(req, "restart")
	case "reload-nginx":
		_, err = commandWithTimeout("nginx", "-t")
		if err == nil {
			err = runFixed("systemctl", "reload", "nginx")
		}
		observed = map[string]any{"mode": "live", "service": "nginx"}
	case "reload-ols":
		_, err = commandWithTimeout("/usr/local/lsws/bin/openlitespeed", "-t")
		if err == nil {
			err = runFixed("systemctl", "reload", "lsws")
		}
		observed = map[string]any{"mode": "live", "service": "lsws"}
	case "issue-certificate":
		observed, err = issueCertificate(req, req.Spec)
	case "provision-data-service":
		observed, err = provisionDataService(req, cfg, root, req.Spec)
	case "prepare-release":
		observed, err = prepareRelease(req, root, req.Spec)
	case "workspace":
		observed, err = runWorkspace(req, root, req.Spec)
	case "backup-data-service":
		observed, err = backupDataService(req, root, req.Spec)
	case "restore-data-service":
		observed, err = restoreDataService(req, root, req.Spec)
	case "deprovision-data-service":
		observed, err = deprovisionDataService(stringValue(req.Spec, "engine"), stringValue(req.Spec, "database"), stringValue(req.Spec, "username"))
	case "install-ssh-key":
		observed, err = installSshKey(req, root, req.Spec)
	case "install-cron":
		observed, err = installCron(req, cfg, root, req.Spec)
	case "remove-cron":
		observed, err = removeCron(req, cfg, root, req.Spec)
	case "observe":
		observed = map[string]any{"mode": "live", "sitePath": root, "type": typeName, "stack": stack, "siteExists": directoryExists(root)}
	default:
		err = errors.New("operation has no implementation")
	}
	if err != nil {
		return Response{Action: req.Action, SiteID: req.SiteID, Error: err.Error(), DryRun: false, Observed: observed}
	}
	return Response{OK: true, Action: req.Action, SiteID: req.SiteID, DryRun: false, Observed: observed}
}

func main() {
	cfg := Config{Socket: os.Getenv("PANEL_AGENT_SOCKET"), SiteRoot: os.Getenv("PANEL_SITE_ROOT"), GeneratedRoot: os.Getenv("PANEL_GENERATED_ROOT"), NginxConfigRoot: os.Getenv("PANEL_NGINX_CONFIG_ROOT"), OlsConfigRoot: os.Getenv("PANEL_OLS_CONFIG_ROOT"), UnitRoot: os.Getenv("PANEL_SYSTEMD_UNIT_ROOT"), PhpFpmPoolRoot: os.Getenv("PANEL_PHP_FPM_POOL_ROOT"), CronRoot: os.Getenv("PANEL_CRON_ROOT"), Live: os.Getenv("PANEL_AGENT_LIVE") == "1"}
	if cfg.Socket == "" {
		cfg.Socket = "/run/quiet-ops/agent.sock"
	}
	if cfg.SiteRoot == "" {
		cfg.SiteRoot = "/var/lib/quiet-ops/sites"
	}
	if cfg.GeneratedRoot == "" {
		cfg.GeneratedRoot = "/var/lib/quiet-ops/generated"
	}
	if cfg.NginxConfigRoot == "" {
		cfg.NginxConfigRoot = "/etc/nginx/conf.d"
	}
	if cfg.OlsConfigRoot == "" {
		cfg.OlsConfigRoot = "/usr/local/lsws/conf/vhosts"
	}
	if cfg.UnitRoot == "" {
		cfg.UnitRoot = "/etc/systemd/system"
	}
	if cfg.PhpFpmPoolRoot == "" {
		cfg.PhpFpmPoolRoot = "/etc/php/8.3/fpm/pool.d"
	}
	if cfg.CronRoot == "" {
		cfg.CronRoot = "/etc/cron.d"
	}
	_ = os.Remove(cfg.Socket)
	if err := os.MkdirAll(filepath.Dir(cfg.Socket), 0750); err != nil {
		panic(err)
	}
	// Web workers need directory traverse permission for per-site PHP-FPM
	// sockets, but the agent socket itself remains mode 0660 and control-group
	// protected. Keep this ACL on every boot because /run is ephemeral.
	if _, aclErr := commandWithTimeout("setfacl", "-m", "u:www-data:--x,u:nobody:--x", filepath.Dir(cfg.Socket)); aclErr != nil {
		panic(fmt.Errorf("grant web socket-directory traversal: %w", aclErr))
	}
	listener, err := net.Listen("unix", cfg.Socket)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	panelGroup, lookupErr := user.LookupGroup("quiet-ops-control")
	if lookupErr != nil {
		panic(fmt.Errorf("quiet-ops-control group is required for the agent socket: %w", lookupErr))
	}
	groupID, parseErr := strconv.Atoi(panelGroup.Gid)
	if parseErr != nil {
		panic(fmt.Errorf("quiet-ops group id is invalid: %w", parseErr))
	}
	if chownErr := os.Chown(cfg.Socket, 0, groupID); chownErr != nil {
		panic(chownErr)
	}
	_ = os.Chmod(cfg.Socket, 0660)
	mode := "dry-run"
	if cfg.Live {
		mode = "live"
	}
	fmt.Printf("panel-agentd listening on %s (%s)\n", cfg.Socket, mode)
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			scanner := bufio.NewScanner(c)
			scanner.Buffer(make([]byte, 4096), 2*1024*1024)
			for scanner.Scan() {
				var req Request
				if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
					_ = json.NewEncoder(c).Encode(Response{Error: "invalid request", DryRun: !cfg.Live})
					continue
				}
				_ = json.NewEncoder(c).Encode(handle(req, cfg))
			}
		}(conn)
	}
}

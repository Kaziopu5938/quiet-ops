package main

import (
	"bytes"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func testConfig(root string, live bool) Config {
	return Config{
		SiteRoot:        filepath.Join(root, "sites"),
		GeneratedRoot:   filepath.Join(root, "generated"),
		NginxConfigRoot: filepath.Join(root, "nginx"),
		OlsConfigRoot:   filepath.Join(root, "ols"),
		UnitRoot:        filepath.Join(root, "units"),
		PhpFpmPoolRoot:  filepath.Join(root, "php-fpm"),
		CronRoot:        filepath.Join(root, "cron.d"),
		Live:            live,
	}
}

func TestDryRunRejectsUnsafeActionsWithoutWriting(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(root, false)
	req := Request{Action: "converge", SiteID: "site_safe123", Spec: map[string]any{
		"type": "wordpress", "stack": "nginx", "nginxConfig": "server {}",
	}}
	response := handle(req, cfg)
	if !response.OK || !response.DryRun {
		t.Fatalf("expected successful dry-run response, got %+v", response)
	}
	if _, err := os.Stat(filepath.Join(root, "sites")); !os.IsNotExist(err) {
		t.Fatalf("dry-run unexpectedly created site state: %v", err)
	}
	bad := handle(Request{Action: "converge", SiteID: "../../etc", Spec: map[string]any{"type": "static", "stack": "nginx"}}, cfg)
	if bad.Error == "" || bad.OK {
		t.Fatalf("expected path rejection, got %+v", bad)
	}
}

func TestLivePublishReleaseAtomicallyReplacesCurrent(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(root, true)
	siteRoot := filepath.Join(cfg.SiteRoot, "site_publish")
	releaseOne := filepath.Join(siteRoot, "releases", "release-1")
	releaseTwo := filepath.Join(siteRoot, "releases", "release-2")
	if err := os.MkdirAll(releaseOne, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(releaseTwo, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseOne, "version"), []byte("one"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseTwo, "version"), []byte("two"), 0640); err != nil {
		t.Fatal(err)
	}
	req := Request{Action: "publish-release", SiteID: "site_publish", Spec: map[string]any{
		"type": "static", "stack": "nginx", "releasePath": releaseOne,
	}}
	first := handle(req, cfg)
	if !first.OK || first.DryRun {
		t.Fatalf("first publish failed: %+v", first)
	}
	req.Spec["releasePath"] = releaseTwo
	second := handle(req, cfg)
	if !second.OK || second.DryRun {
		t.Fatalf("second publish failed: %+v", second)
	}
	current, err := filepath.EvalSymlinks(filepath.Join(siteRoot, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if current != releaseTwo {
		t.Fatalf("current points to %s, want %s", current, releaseTwo)
	}
	if _, err := os.Stat(filepath.Join(siteRoot, ".current-site_publish.previous")); !os.IsNotExist(err) {
		t.Fatalf("previous release staging path remains: %v", err)
	}
}

func TestRuntimeUnitUsesSiteIdentityAndContainedEntry(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sites", "site_node")
	unit, err := systemdUnit("site_node", "qops_site_node", root, "next", map[string]any{"port": "3100"})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"User=qops_site_node", "ExecStart=/usr/bin/node", "PORT=3100", "ProtectHome=yes"} {
		if !contains(unit, expected) {
			t.Fatalf("unit missing %q: %s", expected, unit)
		}
	}
	if _, err := systemdUnit("site_node", "qops_site_node", root, "node", map[string]any{"entry": "../../etc/passwd"}); err == nil {
		t.Fatal("expected runtime entry traversal to be rejected")
	}
	if _, err := systemdUnit("site_node", "qops_site_node", root, "node", map[string]any{"entry": "server.js --inspect"}); err == nil {
		t.Fatal("expected systemd-special runtime entry to be rejected")
	}
	currentUser, currentUserErr := user.Current()
	if currentUserErr != nil {
		t.Fatal(currentUserErr)
	}
	container, err := systemdUnit("site_node", currentUser.Username, root, "next", map[string]any{"isolation": "docker", "image": "node:22-alpine"})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"/usr/bin/docker run", "--user", "--network bridge", "--cap-drop ALL", "node:22-alpine", ".next/standalone/server.js"} {
		if !contains(container, expected) {
			t.Fatalf("container unit missing %q: %s", expected, container)
		}
	}
	restart := handle(Request{Action: "restart-runtime", SiteID: "site_node", Spec: map[string]any{"type": "node", "stack": "node"}}, testConfig(t.TempDir(), false))
	if !restart.OK || !restart.DryRun {
		t.Fatalf("expected runtime restart dry-run, got %+v", restart)
	}
}

func TestRelativeSitePathRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "site")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(root, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0750); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "release")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if _, err := relativeSitePath(root, link); err == nil {
		t.Fatal("expected symlink escape to be rejected")
	}
}

func TestWordPressNginxPoolIsSiteConfined(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sites", "site_wp")
	pool, err := phpFpmPool("site_wp", "qops_site_wp", root)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"[qops_sitewp]", "user = qops_site_wp", "listen = /run/quiet-ops/site_wp.php.sock", "listen.group = www-data", "pm = ondemand", "open_basedir"} {
		if !contains(pool, expected) {
			t.Fatalf("PHP-FPM pool missing %q: %s", expected, pool)
		}
	}
}

func TestCertificateActionValidatesDomainsInDryRun(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(root, false)
	valid := handle(Request{Action: "issue-certificate", SiteID: "site_cert", Spec: map[string]any{"type": "static", "stack": "nginx", "domains": []any{"example.com"}}}, cfg)
	if !valid.OK || !valid.DryRun {
		t.Fatalf("expected certificate dry-run, got %+v", valid)
	}
	invalid := handle(Request{Action: "issue-certificate", SiteID: "site_cert", Spec: map[string]any{"type": "static", "stack": "nginx", "domains": []any{"bad domain"}}}, cfg)
	if invalid.OK || invalid.Error == "" {
		t.Fatalf("expected invalid domain rejection, got %+v", invalid)
	}
}

func TestDataServiceDryRunDoesNotEmitCredentials(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(root, false)
	response := handle(Request{Action: "provision-data-service", SiteID: "site_db", Spec: map[string]any{"type": "wordpress", "stack": "nginx", "engine": "mariadb", "database": "site_db", "username": "site_db_user"}}, cfg)
	if !response.OK || !response.DryRun {
		t.Fatalf("expected data-service dry-run, got %+v", response)
	}
	if _, err := os.Stat(filepath.Join(root, "sites", "site_db", "secrets")); !os.IsNotExist(err) {
		t.Fatalf("dry-run emitted secret directory: %v", err)
	}
}

func TestDataServiceDeprovisionDryRunIsTyped(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(root, false)
	valid := handle(Request{Action: "deprovision-data-service", SiteID: "site_db", Spec: map[string]any{"type": "wordpress", "stack": "nginx", "engine": "mariadb", "database": "site_db", "username": "site_db_user"}}, cfg)
	if !valid.OK || !valid.DryRun {
		t.Fatalf("expected data-service deprovision dry-run, got %+v", valid)
	}
	invalid := handle(Request{Action: "deprovision-data-service", SiteID: "site_db", Spec: map[string]any{"type": "wordpress", "stack": "nginx", "engine": "mariadb", "database": "site-db", "username": "site_db_user"}}, cfg)
	if invalid.OK || invalid.Error == "" {
		t.Fatalf("expected database identifier rejection, got %+v", invalid)
	}
}

func TestPrepareReleaseDryRunValidatesGitAndBuildProfile(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(root, false)
	valid := handle(Request{Action: "prepare-release", SiteID: "site_git", Spec: map[string]any{"type": "next", "stack": "node", "repo": "https://git.example.com/app.git", "branch": "main", "build": "next", "image": "node:22-alpine", "releasePath": filepath.Join(cfg.SiteRoot, "site_git", "releases", "release-1")}}, cfg)
	if !valid.OK || !valid.DryRun {
		t.Fatalf("expected Git dry-run, got %+v", valid)
	}
	invalid := handle(Request{Action: "prepare-release", SiteID: "site_git", Spec: map[string]any{"type": "next", "stack": "node", "repo": "http://git.example.com/app.git", "releasePath": filepath.Join(cfg.SiteRoot, "site_git", "releases", "release-1")}}, cfg)
	if invalid.OK || invalid.Error == "" {
		t.Fatalf("expected Git URL rejection, got %+v", invalid)
	}
}

func TestWorkspaceDryRunIsArgvAllowlisted(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(root, false)
	valid := handle(Request{Action: "workspace", SiteID: "site_shell", Spec: map[string]any{"type": "node", "stack": "node", "argv": []any{"pwd"}}}, cfg)
	if !valid.OK || !valid.DryRun {
		t.Fatalf("expected workspace dry-run, got %+v", valid)
	}
	invalid := handle(Request{Action: "workspace", SiteID: "site_shell", Spec: map[string]any{"type": "node", "stack": "node", "argv": []any{"sh", "-c", "id"}}}, cfg)
	if invalid.OK || invalid.Error == "" {
		t.Fatalf("expected shell rejection, got %+v", invalid)
	}
	escape := handle(Request{Action: "workspace", SiteID: "site_shell", Spec: map[string]any{"type": "node", "stack": "node", "argv": []any{"cat", "../../etc/passwd"}}}, cfg)
	if escape.OK || escape.Error == "" {
		t.Fatalf("expected workspace path rejection, got %+v", escape)
	}
}

func TestDatabaseBackupDryRunValidatesConfinedOutput(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(root, false)
	valid := handle(Request{Action: "backup-data-service", SiteID: "site_db", Spec: map[string]any{"type": "wordpress", "stack": "nginx", "engine": "postgresql", "database": "site_db", "username": "site_db_user", "outputPath": filepath.Join(cfg.SiteRoot, "site_db", "backups", "backup.dump")}}, cfg)
	if !valid.OK || !valid.DryRun {
		t.Fatalf("expected database-backup dry-run, got %+v", valid)
	}
	invalid := handle(Request{Action: "backup-data-service", SiteID: "site_db", Spec: map[string]any{"type": "wordpress", "stack": "nginx", "engine": "postgresql", "database": "site_db", "username": "site_db_user", "outputPath": filepath.Join(cfg.SiteRoot, "other", "backup.dump")}}, cfg)
	if invalid.OK || invalid.Error == "" {
		t.Fatalf("expected output confinement rejection, got %+v", invalid)
	}
}

func TestDatabaseRestoreDryRunValidatesConfinedInput(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(root, false)
	valid := handle(Request{Action: "restore-data-service", SiteID: "site_db", Spec: map[string]any{"type": "wordpress", "stack": "nginx", "engine": "postgresql", "database": "site_db", "username": "site_db_user", "inputPath": filepath.Join(cfg.SiteRoot, "site_db", "backups", "backup.dump")}}, cfg)
	if !valid.OK || !valid.DryRun {
		t.Fatalf("expected data restore dry-run, got %+v", valid)
	}
	invalid := handle(Request{Action: "restore-data-service", SiteID: "site_db", Spec: map[string]any{"type": "wordpress", "stack": "nginx", "engine": "postgresql", "database": "site_db", "username": "site_db_user", "inputPath": filepath.Join(cfg.SiteRoot, "other", "backup.dump")}}, cfg)
	if invalid.OK || invalid.Error == "" {
		t.Fatalf("expected input confinement rejection, got %+v", invalid)
	}
}

func TestCronDryRunAllowsTypedCommandsOnly(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(root, false)
	valid := handle(Request{Action: "install-cron", SiteID: "site_cron", Spec: map[string]any{"type": "wordpress", "stack": "nginx", "cronId": "cron_job1", "expression": "*/5 * * * *", "command": "wp cron event run --due-now"}}, cfg)
	if !valid.OK || !valid.DryRun {
		t.Fatalf("expected cron dry-run, got %+v", valid)
	}
	unsafe := handle(Request{Action: "install-cron", SiteID: "site_cron", Spec: map[string]any{"type": "wordpress", "stack": "nginx", "cronId": "cron_job1", "expression": "*/5 * * * *", "command": "sh -c id"}}, cfg)
	if unsafe.OK || unsafe.Error == "" {
		t.Fatalf("expected cron executable rejection, got %+v", unsafe)
	}
	badExpression := handle(Request{Action: "install-cron", SiteID: "site_cron", Spec: map[string]any{"type": "wordpress", "stack": "nginx", "cronId": "cron_job1", "expression": "@reboot", "command": "wp cron event run"}}, cfg)
	if badExpression.OK || badExpression.Error == "" {
		t.Fatalf("expected cron expression rejection, got %+v", badExpression)
	}
}

func TestRedisRestoreRESPEncoding(t *testing.T) {
	var output bytes.Buffer
	if err := writeRESP(&output, []byte("RESTORE"), []byte("site_redis:key"), []byte("0"), []byte{0x01, 0x02}, []byte("REPLACE")); err != nil {
		t.Fatal(err)
	}
	if output.String() != "*5\r\n$7\r\nRESTORE\r\n$14\r\nsite_redis:key\r\n$1\r\n0\r\n$2\r\n\x01\x02\r\n$7\r\nREPLACE\r\n" {
		t.Fatalf("unexpected RESP stream: %q", output.String())
	}
}

func TestSshKeyDryRunAcceptsPublicKeysOnly(t *testing.T) {
	root := t.TempDir()
	cfg := testConfig(root, false)
	valid := handle(Request{Action: "install-ssh-key", SiteID: "site_ssh", Spec: map[string]any{"type": "static", "stack": "nginx", "publicKey": "ssh-ed25519 eA== operator"}}, cfg)
	if !valid.OK || !valid.DryRun {
		t.Fatalf("expected ssh key dry-run, got %+v", valid)
	}
	invalid := handle(Request{Action: "install-ssh-key", SiteID: "site_ssh", Spec: map[string]any{"type": "static", "stack": "nginx", "publicKey": "not-a-key"}}, cfg)
	if invalid.OK || invalid.Error == "" {
		t.Fatalf("expected ssh key rejection, got %+v", invalid)
	}
}

func contains(value, needle string) bool {
	return len(value) >= len(needle) && stringIndex(value, needle) >= 0
}

func stringIndex(value, needle string) int {
	for index := 0; index+len(needle) <= len(value); index++ {
		if value[index:index+len(needle)] == needle {
			return index
		}
	}
	return -1
}

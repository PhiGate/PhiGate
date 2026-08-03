package sandbox

import (
	"regexp"
	"strings"
)

// dangerousRoots are paths whose recursive deletion is catastrophic rather than
// merely destructive. "rm -rf /var/cache/nginx" is a normal remediation;
// "rm -rf /" ends the host.
var dangerousRoots = []string{
	"/", "/*", "/.", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
	"/opt", "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var",
	"/var/lib", "/var/log", "/data", "/tmp", "/mnt", "/media", "/usr/local",
	"~", "~/", "$HOME", "C:\\", "C:/",
}

// isDangerousPath reports whether p is a system root or an unbounded glob.
func isDangerousPath(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	clean := strings.TrimRight(p, "/")
	if clean == "" {
		clean = "/"
	}
	for _, d := range dangerousRoots {
		if p == d || clean == strings.TrimRight(d, "/") {
			return true
		}
	}
	// A glob directly under a system directory: /etc/*, /var/*
	if strings.HasSuffix(p, "/*") {
		parent := strings.TrimSuffix(p, "/*")
		for _, d := range dangerousRoots {
			if parent == strings.TrimRight(d, "/") {
				return true
			}
		}
	}
	return false
}

var (
	forkBombRe = forkBombPattern
	// Redirection is stripped by the lexer, so this rule works on raw segment
	// text rather than on an argv.
	blockDeviceRedirectRe = regexp.MustCompile(`>\s*/dev/(?:sd|nvme|hd|vd|mmcblk|disk)`)
	sqlDropRe             = regexp.MustCompile(`(?i)\bdrop\s+(?:table|database|schema)\b`)
	sqlTruncRe            = regexp.MustCompile(`(?i)\btruncate\s+table\b`)
	// DELETE / UPDATE with no WHERE clause before the statement terminator.
	sqlNoWhereRe = regexp.MustCompile(`(?is)\b(?:delete\s+from|update)\s+[a-z_][\w.\"` + "`" + `]*\s*(?:set\s+[^;]*?)?;`)
	sqlWhereRe   = regexp.MustCompile(`(?i)\bwhere\b`)
)

// DefaultRules is PhiGate's baseline rule set.
//
// Severity assignment follows one principle: block only what is catastrophic
// and essentially never a correct answer. Everything that is destructive but
// routinely legitimate — restarting a service, deleting a scoped directory,
// rebooting a node — warns instead. The previous all-or-nothing deny list is
// why "reboot the node" was blocked, and blocking correct advice is how a
// guardrail loses the operators' trust.
func DefaultRules() []Rule {
	return []Rule{
		{
			Name:        "rm_recursive_force_root",
			Severity:    SeverityBlock,
			Description: "recursive forced delete rooted at a system directory",
			MatchCommand: func(c Command) bool {
				if c.Name() != "rm" {
					return false
				}
				if !c.HasFlag("rR", "recursive") {
					return false
				}
				for _, op := range c.Operands() {
					if isDangerousPath(op) {
						return true
					}
				}
				return false
			},
		},
		{
			Name:        "rm_recursive_force",
			Severity:    SeverityWarn,
			Description: "recursive forced delete; verify the target path before running",
			MatchCommand: func(c Command) bool {
				return c.Name() == "rm" &&
					c.HasFlag("rR", "recursive") && c.HasFlag("f", "force")
			},
		},
		{
			Name:        "find_delete_root",
			Severity:    SeverityBlock,
			Description: "find rooted at a system directory with -delete or -exec rm",
			MatchCommand: func(c Command) bool {
				if c.Name() != "find" {
					return false
				}
				destructive := c.HasArg("-delete")
				if !destructive {
					for i, a := range c.Argv {
						if (a == "-exec" || a == "-execdir" || a == "-ok") && i+1 < len(c.Argv) {
							if base := c.Argv[i+1]; strings.HasSuffix(base, "rm") || strings.HasSuffix(base, "shred") {
								destructive = true
							}
						}
					}
				}
				if !destructive {
					return false
				}
				for _, op := range c.Operands() {
					if isDangerousPath(op) {
						return true
					}
				}
				return false
			},
		},
		{
			Name:        "mkfs",
			Severity:    SeverityBlock,
			Description: "creating a filesystem destroys everything on the target device",
			MatchCommand: func(c Command) bool {
				n := c.Name()
				if !strings.HasPrefix(n, "mkfs") && n != "mkswap" && n != "wipefs" {
					return false
				}
				for _, op := range c.Operands() {
					if strings.HasPrefix(op, "/dev/") {
						return true
					}
				}
				return n == "wipefs"
			},
		},
		{
			Name:        "dd_to_device",
			Severity:    SeverityBlock,
			Description: "raw write to a block device overwrites the disk irrecoverably",
			MatchCommand: func(c Command) bool {
				if c.Name() != "dd" {
					return false
				}
				for _, a := range c.Argv {
					if strings.HasPrefix(a, "of=/dev/") {
						return true
					}
				}
				return false
			},
		},
		{
			Name:        "write_block_device",
			Severity:    SeverityBlock,
			Description: "redirecting output into a block device corrupts the filesystem on it",
			MatchSegment: func(s Segment) bool {
				return blockDeviceRedirectRe.MatchString(s.Text)
			},
		},
		{
			Name:        "disk_partitioning",
			Severity:    SeverityBlock,
			Description: "non-interactive partition table modification",
			MatchCommand: func(c Command) bool {
				n := c.Name()
				if n != "parted" && n != "fdisk" && n != "sfdisk" {
					return false
				}
				return c.HasFlag("s", "script") || n == "sfdisk"
			},
		},
		{
			Name:        "fork_bomb",
			Severity:    SeverityBlock,
			Description: "fork bomb: exhausts the process table and requires a hard reset",
			MatchSegment: func(s Segment) bool {
				return forkBombRe.MatchString(s.Text)
			},
		},
		{
			Name:        "recursive_perm_root",
			Severity:    SeverityBlock,
			Description: "recursive ownership or permission change rooted at a system directory",
			MatchCommand: func(c Command) bool {
				n := c.Name()
				if n != "chmod" && n != "chown" && n != "chgrp" {
					return false
				}
				if !c.HasFlag("R", "recursive") {
					return false
				}
				ops := c.Operands()
				// chmod -R 777 /  -> the last operand is the target.
				for i, op := range ops {
					if i == 0 && n != "chmod" {
						continue // owner spec
					}
					if isDangerousPath(op) {
						return true
					}
				}
				return false
			},
		},
		{
			Name:        "pipe_to_shell",
			Severity:    SeverityBlock,
			Description: "piping a download straight into a shell executes unreviewed remote code",
			MatchCommand: func(c Command) bool {
				n := c.Name()
				if n != "sh" && n != "bash" && n != "zsh" && n != "dash" && n != "ksh" {
					return false
				}
				if len(c.PipedFrom) == 0 {
					return false
				}
				src := Command{Argv: c.PipedFrom}.Name()
				return src == "curl" || src == "wget" || src == "fetch"
			},
		},
		{
			Name:        "kubectl_delete_all",
			Severity:    SeverityBlock,
			Description: "deleting every resource of a kind, or every namespace",
			MatchCommand: func(c Command) bool {
				if c.Name() != "kubectl" || !c.HasArg("delete") {
					return false
				}
				return c.HasFlag("", "all") || c.HasArg("--all-namespaces") || c.HasArg("-A")
			},
		},
		{
			Name:        "firewall_flush",
			Severity:    SeverityBlock,
			Description: "flushing firewall rules can sever remote access to the host",
			MatchCommand: func(c Command) bool {
				switch c.Name() {
				case "iptables", "ip6tables", "nft":
					return c.HasFlag("F", "flush") || c.HasArg("flush")
				case "ufw":
					return c.HasArg("disable") || c.HasArg("reset")
				case "firewall-cmd":
					return c.HasArg("--panic-on")
				}
				return false
			},
		},
		{
			Name:         "sql_drop",
			Severity:     SeverityBlock,
			Description:  "DROP removes a table, schema or database and its data",
			MatchSegment: func(s Segment) bool { return sqlDropRe.MatchString(s.Text) },
		},
		{
			Name:         "sql_truncate",
			Severity:     SeverityBlock,
			Description:  "TRUNCATE empties a table and is not transactional on all engines",
			MatchSegment: func(s Segment) bool { return sqlTruncRe.MatchString(s.Text) },
		},
		{
			Name:        "sql_write_without_where",
			Severity:    SeverityBlock,
			Description: "DELETE or UPDATE with no WHERE clause affects every row",
			MatchSegment: func(s Segment) bool {
				for _, stmt := range sqlNoWhereRe.FindAllString(s.Text, -1) {
					if !sqlWhereRe.MatchString(stmt) {
						return true
					}
				}
				return false
			},
		},
		{
			Name:        "credential_exfiltration",
			Severity:    SeverityBlock,
			Description: "reading credential material and sending it off-host",
			MatchCommand: func(c Command) bool {
				n := c.Name()
				if n != "curl" && n != "wget" && n != "nc" && n != "ncat" {
					return false
				}
				joined := strings.ToLower(strings.Join(c.Argv, " "))
				for _, needle := range []string{
					"/etc/shadow", "/etc/passwd", "id_rsa", ".aws/credentials",
					".ssh/", ".kube/config", ".env",
				} {
					if strings.Contains(joined, needle) {
						return true
					}
				}
				return false
			},
		},
		{
			Name:        "history_tampering",
			Severity:    SeverityBlock,
			Description: "clearing shell history or system logs destroys the audit trail",
			MatchCommand: func(c Command) bool {
				joined := strings.Join(c.Argv, " ")
				switch c.Name() {
				case "history":
					return c.HasFlag("c", "clear")
				case "journalctl":
					return strings.Contains(joined, "--vacuum-time=1s") || strings.Contains(joined, "--rotate")
				case "shred":
					return strings.Contains(joined, "/var/log")
				}
				return false
			},
		},
		{
			Name:        "user_deletion",
			Severity:    SeverityWarn,
			Description: "removing a user account and possibly its home directory",
			MatchCommand: func(c Command) bool {
				n := c.Name()
				return n == "userdel" || n == "groupdel" || n == "deluser"
			},
		},
		{
			Name:        "host_power_state",
			Severity:    SeverityWarn,
			Description: "changes host power state; correct in many remediations, so warn rather than block",
			MatchCommand: func(c Command) bool {
				switch c.Name() {
				case "shutdown", "poweroff", "halt":
					return true
				case "reboot":
					return true
				case "init":
					ops := c.Operands()
					return len(ops) > 0 && (ops[0] == "0" || ops[0] == "6")
				case "systemctl":
					return c.HasArg("poweroff") || c.HasArg("reboot") || c.HasArg("halt")
				}
				return false
			},
		},
		{
			Name:        "service_stop",
			Severity:    SeverityWarn,
			Description: "stopping or disabling a service causes an outage if it is load-bearing",
			MatchCommand: func(c Command) bool {
				if c.Name() != "systemctl" && c.Name() != "service" {
					return false
				}
				return c.HasArg("stop") || c.HasArg("disable") || c.HasArg("mask")
			},
		},
		{
			Name:        "container_prune",
			Severity:    SeverityWarn,
			Description: "pruning removes stopped containers, images and volumes, including data",
			MatchCommand: func(c Command) bool {
				n := c.Name()
				if n != "docker" && n != "podman" {
					return false
				}
				return c.HasArg("prune") || (c.HasArg("rm") && c.HasFlag("f", "force"))
			},
		},
		{
			Name:        "terraform_destroy",
			Severity:    SeverityBlock,
			Description: "auto-approved terraform destroy tears down managed infrastructure",
			MatchCommand: func(c Command) bool {
				return c.Name() == "terraform" && c.HasArg("destroy") && c.HasArg("-auto-approve")
			},
		},
		{
			Name:        "git_force_push",
			Severity:    SeverityWarn,
			Description: "force push overwrites remote history",
			MatchCommand: func(c Command) bool {
				return c.Name() == "git" && c.HasArg("push") &&
					(c.HasFlag("f", "force") || c.HasArg("--force-with-lease"))
			},
		},
	}
}

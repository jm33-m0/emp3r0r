package assistant

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxLDAPEntries = 5000
	maxAccounts    = 100
	maxGroups      = 100
	maxFindings    = 100
	maxTrusts      = 20
	maxTemplates   = 20
	maxAttributes  = 100

	uacAccountDisabled            = 0x0002
	uacPasswordNotRequired        = 0x0020
	uacServerTrustAccount         = 0x2000
	uacPasswordNeverExpires       = 0x10000
	uacTrustedForDelegation       = 0x80000
	uacDontRequirePreAuth         = 0x400000
	uacTrustedToAuthForDelegation = 0x1000000

	// 100-nanosecond intervals between 1601-01-01 and 1970-01-01.
	filetimeEpoch = 116444736000000000
)

type finding struct {
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Attribute string `json:"attribute,omitempty"`
}

type ldapAccount struct {
	DN                   string `json:"dn"`
	SAM                  string `json:"sam,omitempty"`
	Kind                 string `json:"kind"`
	Enabled              bool   `json:"enabled"`
	UAC                  int64  `json:"uac,omitempty"`
	Kerberoastable       bool   `json:"kerberoastable,omitempty"`
	ASREPRoastable       bool   `json:"asrep_roastable,omitempty"`
	AdminCount           bool   `json:"admin_count,omitempty"`
	Delegation           string `json:"delegation,omitempty"`
	SIDHistory           bool   `json:"sid_history,omitempty"`
	PasswordNeverExpires bool   `json:"password_never_expires,omitempty"`
	PasswordNotRequired  bool   `json:"password_not_required,omitempty"`
	PwdLastSet           string `json:"pwd_last_set,omitempty"`
	LastLogon            string `json:"last_logon,omitempty"`
	LAPSReadable         bool   `json:"laps_readable,omitempty"`
	KeyCredential        bool   `json:"key_credential,omitempty"`
	GMSA                 bool   `json:"gmsa,omitempty"`
	DomainController     bool   `json:"domain_controller,omitempty"`
	PrivilegedGroup      string `json:"privileged_group,omitempty"`
}

type ldapGroup struct {
	DN         string `json:"dn"`
	SAM        string `json:"sam,omitempty"`
	AdminCount bool   `json:"admin_count,omitempty"`
	Members    int    `json:"members,omitempty"`
	Privileged bool   `json:"privileged,omitempty"`
}

type ldapTrust struct {
	DN         string `json:"dn"`
	Partner    string `json:"partner,omitempty"`
	Direction  string `json:"direction,omitempty"`
	Attributes string `json:"attributes,omitempty"`
}

type ldapTemplate struct {
	DN                  string `json:"dn"`
	Name                string `json:"name,omitempty"`
	EnrolleeSubject     bool   `json:"enrollee_supplies_subject,omitempty"`
	RequiresApproval    bool   `json:"requires_approval,omitempty"`
	ClientAuthEKU       bool   `json:"client_auth_eku,omitempty"`
	AnyPurposeEKU       bool   `json:"any_purpose_eku,omitempty"`
	ESC1Candidate       bool   `json:"esc1_candidate,omitempty"`
	RawNameFlag         int64  `json:"ms_pki_certificate_name_flag,omitempty"`
	RawEnrollmentFlag   int64  `json:"ms_pki_enrollment_flag,omitempty"`
	RawRASignatureCount int64  `json:"ms_pki_ra_signature,omitempty"`
}

type ldapDomain struct {
	DN                  string `json:"dn,omitempty"`
	MinPwdLength        int64  `json:"min_pwd_length,omitempty"`
	LockoutThreshold    int64  `json:"lockout_threshold,omitempty"`
	MaxPwdAgeDays       int64  `json:"max_pwd_age_days,omitempty"`
	MachineAccountQuota int64  `json:"machine_account_quota,omitempty"`
	HasQuota            bool   `json:"has_machine_account_quota,omitempty"`
}

type ldapEntry struct {
	attrs map[string][]string
}

func (e ldapEntry) first(name string) string {
	vals := e.attrs[name]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func (e ldapEntry) has(name string) bool {
	return len(e.attrs[name]) > 0
}

func (e ldapEntry) classes() []string {
	var out []string
	for _, v := range e.attrs["objectClass"] {
		for _, part := range strings.Split(v, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func (e ldapEntry) hasClass(name string) bool {
	name = strings.ToLower(name)
	for _, c := range e.classes() {
		if c == name {
			return true
		}
	}
	return false
}

func looksLikeLDAP(out string) bool {
	if strings.Contains(out, "--------------------") && strings.Contains(strings.ToLower(out), "objectclass:") {
		return true
	}
	// A single entry without the separator still looks like LDAP when it has
	// several attribute lines.
	attrs := 0
	for _, line := range strings.Split(out, "\n") {
		if _, _, ok := splitLDAPAttr(line); ok {
			attrs++
		}
		if attrs >= 5 {
			return true
		}
	}
	return false
}

func summarizeLDAP(out string, truncated bool) any {
	entries := parseLDAPEntries(out)
	notes := make([]string, 0, 4)
	if truncated {
		notes = append(notes, "Input was truncated before parsing; counts and findings are lower bounds.")
	}
	if len(entries) > maxLDAPEntries {
		entries = entries[:maxLDAPEntries]
		notes = append(notes, fmt.Sprintf("Parsed the first %d entries only.", maxLDAPEntries))
	}

	attrs := make(map[string]struct{})
	accounts := make([]ldapAccount, 0, 16)
	groups := make([]ldapGroup, 0, 16)
	trusts := make([]ldapTrust, 0, 4)
	var templates []ldapTemplate
	var domain *ldapDomain
	findings := make([]finding, 0, 16)

	addFinding := func(sev, title, detail, attr string) {
		if len(findings) >= maxFindings {
			return
		}
		for _, f := range findings {
			if f.Severity == sev && f.Title == title && f.Detail == detail {
				return
			}
		}
		findings = append(findings, finding{Severity: sev, Title: title, Detail: detail, Attribute: attr})
	}

	for _, e := range entries {
		for name := range e.attrs {
			attrs[name] = struct{}{}
		}
		if e.hasClass("trusteddomain") {
			trusts = append(trusts, ldapTrust{
				DN:         e.first("distinguishedName"),
				Partner:    e.first("trustPartner"),
				Direction:  trustDirection(e.first("trustDirection")),
				Attributes: trustAttributes(e.first("trustAttributes")),
			})
			continue
		}
		if e.hasClass("pkicertificatetemplate") {
			t := summarizeTemplate(e)
			templates = append(templates, t)
			if t.ESC1Candidate {
				if t.RequiresApproval {
					addFinding("medium", "ADCS template matches ESC1 but requires approval",
						fmt.Sprintf("%s (%s)", t.Name, t.DN), "msPKI-Certificate-Name-Flag")
				} else {
					addFinding("high", "ADCS template matches ESC1",
						fmt.Sprintf("%s (%s): enrollee supplies subject, no RA signature, client-auth EKU", t.Name, t.DN),
						"msPKI-Certificate-Name-Flag")
				}
			}
			continue
		}
		if e.hasClass("group") {
			g := ldapGroup{
				DN:         e.first("distinguishedName"),
				SAM:        firstNonEmpty(e.first("sAMAccountName"), commonName(e.first("distinguishedName"))),
				AdminCount: e.first("adminCount") == "1",
				Members:    len(e.attrs["member"]),
			}
			lower := strings.ToLower(g.SAM + " " + g.DN)
			for _, p := range privilegedGroupNames {
				if strings.Contains(lower, p) {
					g.Privileged = true
					break
				}
			}
			groups = append(groups, g)
			continue
		}
		if d := summarizeDomain(e); d != nil {
			if domain == nil {
				domain = d
				if d.MinPwdLength > 0 && d.MinPwdLength < 8 {
					addFinding("medium", "Weak minimum password length",
						fmt.Sprintf("minPwdLength=%d", d.MinPwdLength), "minPwdLength")
				}
				if d.LockoutThreshold == 0 {
					addFinding("medium", "Account lockout is disabled",
						"lockoutThreshold=0", "lockoutThreshold")
				}
			}
			continue
		}
		if !e.hasClass("user") && !e.hasClass("computer") && !e.hasClass("person") && e.first("sAMAccountName") == "" {
			continue
		}

		acct := summarizeAccount(e)
		if acct.SAM == "" && acct.DN == "" {
			continue
		}
		accounts = append(accounts, acct)
		addAccountFindings(acct, addFinding)

		if e.has("userPassword") || e.has("unicodePwd") {
			addFinding("high", "Password attribute is readable",
				fmt.Sprintf("%s exposes userPassword/unicodePwd", firstNonEmpty(acct.SAM, acct.DN)),
				"userPassword")
		}
		if e.has("nTSecurityDescriptor") {
			addFinding("info", "Security descriptor returned",
				fmt.Sprintf("%s includes nTSecurityDescriptor; review ACLs manually", firstNonEmpty(acct.SAM, acct.DN)),
				"nTSecurityDescriptor")
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		if severityRank(findings[i].Severity) != severityRank(findings[j].Severity) {
			return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
		}
		return findings[i].Title < findings[j].Title
	})
	if len(accounts) > maxAccounts {
		accounts = accounts[:maxAccounts]
		notes = append(notes, fmt.Sprintf("Showing the first %d accounts.", maxAccounts))
	}
	if len(groups) > maxGroups {
		groups = groups[:maxGroups]
		notes = append(notes, fmt.Sprintf("Showing the first %d groups.", maxGroups))
	}
	if len(trusts) > maxTrusts {
		trusts = trusts[:maxTrusts]
	}
	if len(templates) > maxTemplates {
		templates = templates[:maxTemplates]
	}
	attrList := make([]string, 0, len(attrs))
	for name := range attrs {
		attrList = append(attrList, name)
	}
	sort.Strings(attrList)
	if len(attrList) > maxAttributes {
		attrList = attrList[:maxAttributes]
	}

	return map[string]any{
		"format":         "ldap",
		"entries":        len(entries),
		"attributes":     attrList,
		"accounts":       accounts,
		"groups":         groups,
		"trusts":         trusts,
		"adcs_templates": templates,
		"domain":         domain,
		"findings":       findings,
		"notes":          notes,
		"truncated":      truncated,
	}
}

func parseLDAPEntries(out string) []ldapEntry {
	var entries []ldapEntry
	var current map[string][]string
	flush := func() {
		if len(current) > 0 {
			entries = append(entries, ldapEntry{attrs: current})
		}
		current = nil
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--------------------") {
			flush()
			current = make(map[string][]string)
			continue
		}
		name, value, ok := splitLDAPAttr(line)
		if !ok {
			continue
		}
		if current == nil {
			// Some producers omit the separator. Start on the first attribute.
			current = make(map[string][]string)
		}
		current[name] = append(current[name], value)
	}
	flush()
	return entries
}

func splitLDAPAttr(line string) (string, string, bool) {
	if line == "" {
		return "", "", false
	}
	switch line[0] {
	case ' ', '\t', '[', '#':
		return "", "", false
	}
	idx := strings.Index(line, ": ")
	if idx <= 0 {
		if strings.HasSuffix(line, ":") {
			name := strings.TrimSpace(line[:len(line)-1])
			if validAttrName(name) {
				return name, "", true
			}
		}
		return "", "", false
	}
	name := strings.TrimSpace(line[:idx])
	if !validAttrName(name) {
		return "", "", false
	}
	return name, strings.TrimSpace(line[idx+2:]), true
}

func validAttrName(name string) bool {
	if name == "" {
		return false
	}
	first := name[0]
	if (first < 'a' || first > 'z') && (first < 'A' || first > 'Z') {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

func summarizeAccount(e ldapEntry) ldapAccount {
	uac, hasUAC := parseIntAttr(e, "userAccountControl")
	acct := ldapAccount{
		DN:                   e.first("distinguishedName"),
		SAM:                  e.first("sAMAccountName"),
		Kind:                 "user",
		Enabled:              !hasUAC || uac&uacAccountDisabled == 0,
		UAC:                  uac,
		AdminCount:           e.first("adminCount") == "1",
		SIDHistory:           e.has("sIDHistory"),
		PwdLastSet:           filetimeDescription(e.first("pwdLastSet")),
		LastLogon:            filetimeDescription(firstNonEmpty(e.first("lastLogonTimestamp"), e.first("lastLogon"))),
		LAPSReadable:         e.has("ms-Mcs-AdmPwd") || e.has("msLAPS-Password") || e.has("msLAPS-EncryptedPassword"),
		KeyCredential:        e.has("msDS-KeyCredentialLink"),
		GMSA:                 e.hasClass("msds-groupmanagedserviceaccount"),
		DomainController:     uac&uacServerTrustAccount != 0 || e.first("primaryGroupID") == "516" || strings.Contains(strings.ToLower(e.first("distinguishedName")), "ou=domain controllers"),
		PasswordNeverExpires: uac&uacPasswordNeverExpires != 0,
		PasswordNotRequired:  uac&uacPasswordNotRequired != 0,
	}
	if e.hasClass("computer") {
		acct.Kind = "computer"
	}

	spn := e.first("servicePrincipalName")
	acct.Kerberoastable = spn != "" && acct.Enabled && !acct.DomainController &&
		acct.Kind != "computer" && !strings.EqualFold(acct.SAM, "krbtgt")
	acct.ASREPRoastable = hasUAC && uac&uacDontRequirePreAuth != 0 && acct.Enabled && acct.Kind != "computer"

	switch {
	case e.has("msDS-AllowedToActOnBehalfOfOtherIdentity"):
		acct.Delegation = "rbcd"
	case e.has("msDS-AllowedToDelegateTo"):
		acct.Delegation = "constrained"
	case hasUAC && uac&uacTrustedForDelegation != 0:
		acct.Delegation = "unconstrained"
	case hasUAC && uac&uacTrustedToAuthForDelegation != 0:
		acct.Delegation = "protocol-transition"
	}

	lowerMemberOf := strings.ToLower(strings.Join(e.attrs["memberOf"], " "))
	for _, p := range privilegedGroupNames {
		if strings.Contains(lowerMemberOf, "cn="+p+",") || strings.HasSuffix(lowerMemberOf, "cn="+p) {
			acct.PrivilegedGroup = p
			break
		}
	}
	return acct
}

func addAccountFindings(acct ldapAccount, add func(sev, title, detail, attr string)) {
	name := firstNonEmpty(acct.SAM, acct.DN)
	switch acct.Delegation {
	case "unconstrained":
		if acct.DomainController {
			add("info", "Domain controller has unconstrained delegation (expected)", name, "userAccountControl")
		} else {
			add("high", "Unconstrained delegation", name, "userAccountControl")
		}
	case "rbcd":
		add("high", "Resource-based constrained delegation", name, "msDS-AllowedToActOnBehalfOfOtherIdentity")
	case "constrained":
		add("medium", "Constrained delegation", name, "msDS-AllowedToDelegateTo")
	case "protocol-transition":
		add("medium", "Protocol transition delegation", name, "userAccountControl")
	}
	if acct.ASREPRoastable {
		add("high", "AS-REP roastable account", name, "userAccountControl")
	}
	if acct.Kerberoastable {
		add("medium", "Kerberoastable account", name, "servicePrincipalName")
	}
	if acct.PrivilegedGroup != "" {
		add("high", "Direct member of "+acct.PrivilegedGroup, name, "memberOf")
	}
	if acct.AdminCount {
		add("medium", "adminCount=1 (protected account)", name, "adminCount")
	}
	if acct.LAPSReadable {
		add("high", "LAPS password readable", name, "ms-Mcs-AdmPwd")
	}
	if acct.KeyCredential {
		add("medium", "Shadow credentials link present", name, "msDS-KeyCredentialLink")
	}
	if acct.SIDHistory {
		add("medium", "SID history present", name, "sIDHistory")
	}
	if acct.PasswordNotRequired {
		add("medium", "Password not required", name, "userAccountControl")
	}
	if acct.PwdLastSet == "0 (never / must change at next logon)" {
		add("medium", "Password must change at next logon", name, "pwdLastSet")
	}
}

func summarizeDomain(e ldapEntry) *ldapDomain {
	if !e.hasClass("domaindns") && !e.has("minPwdLength") && !e.has("pwdProperties") {
		return nil
	}
	d := &ldapDomain{DN: e.first("distinguishedName")}
	if v, ok := parseIntAttr(e, "minPwdLength"); ok {
		d.MinPwdLength = v
	}
	if v, ok := parseIntAttr(e, "lockoutThreshold"); ok {
		d.LockoutThreshold = v
	}
	if age, ok := parseIntAttr(e, "maxPwdAge"); ok && age < 0 && age > math.MinInt64 {
		// maxPwdAge is a negative 100-ns interval; MinInt64 means passwords never expire.
		d.MaxPwdAgeDays = (-age) / (86400 * 10000000)
	}
	if quota, ok := parseIntAttr(e, "ms-DS-MachineAccountQuota"); ok {
		d.MachineAccountQuota = quota
		d.HasQuota = true
	}
	return d
}

func summarizeTemplate(e ldapEntry) ldapTemplate {
	nameFlag, _ := parseIntAttr(e, "msPKI-Certificate-Name-Flag")
	enrollFlag, _ := parseIntAttr(e, "msPKI-Enrollment-Flag")
	raSig, _ := parseIntAttr(e, "msPKI-RA-Signature")
	eku := strings.ToLower(e.first("pKIExtendedKeyUsage"))
	t := ldapTemplate{
		DN:                  e.first("distinguishedName"),
		Name:                firstNonEmpty(e.first("name"), commonName(e.first("distinguishedName"))),
		EnrolleeSubject:     nameFlag&0x1 != 0,
		RequiresApproval:    enrollFlag&0x2 != 0,
		ClientAuthEKU:       strings.Contains(eku, "1.3.6.1.5.5.7.3.2"),
		AnyPurposeEKU:       strings.Contains(eku, "2.5.29.37.0"),
		RawNameFlag:         nameFlag,
		RawEnrollmentFlag:   enrollFlag,
		RawRASignatureCount: raSig,
	}
	t.ESC1Candidate = t.EnrolleeSubject && raSig == 0 && (t.ClientAuthEKU || t.AnyPurposeEKU)
	return t
}

func parseIntAttr(e ldapEntry, name string) (int64, bool) {
	raw := strings.TrimSpace(e.first(name))
	if raw == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 0, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func filetimeDescription(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	switch raw {
	case "0":
		return "0 (never / must change at next logon)"
	case "9223372036854775807":
		return "never"
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < filetimeEpoch {
		return raw
	}
	t := time.Unix(0, (n-filetimeEpoch)*100).UTC()
	days := int(time.Since(t).Hours() / 24)
	if days < 0 {
		days = 0
	}
	return fmt.Sprintf("%s (%d days ago)", t.Format("2006-01-02"), days)
}

func trustDirection(raw string) string {
	switch strings.TrimSpace(raw) {
	case "1":
		return "inbound"
	case "2":
		return "outbound"
	case "3":
		return "bidirectional"
	default:
		return raw
	}
}

func trustAttributes(raw string) string {
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 0, 64)
	if err != nil {
		return raw
	}
	bits := []struct {
		flag int64
		name string
	}{
		{0x1, "non-transitive"},
		{0x2, "uplevel-only"},
		{0x4, "quarantined"},
		{0x8, "forest-transitive"},
		{0x10, "cross-organization"},
		{0x20, "within-forest"},
		{0x40, "treat-as-external"},
		{0x400, "tgt-delegation"},
	}
	var names []string
	for _, b := range bits {
		if n&b.flag != 0 {
			names = append(names, b.name)
		}
	}
	if len(names) == 0 {
		return raw
	}
	return strings.Join(names, ", ")
}

func commonName(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "cn=") {
			return part[3:]
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func severityRank(s string) int {
	switch s {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	default:
		return 3
	}
}

var privilegedGroupNames = []string{
	"domain admins",
	"enterprise admins",
	"schema admins",
	"administrators",
	"account operators",
	"backup operators",
	"server operators",
	"print operators",
	"group policy creator owners",
	"dnsadmins",
	"exchange organization management",
	"organization management",
}

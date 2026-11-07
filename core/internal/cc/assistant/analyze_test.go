package assistant

import (
	"strings"
	"testing"
)

const ldapFixture = `[*] Distinguished name: DC=corp,DC=local
[*] targeting DC: dc01.corp.local
[*] Filter: (objectClass=user)

--------------------
distinguishedName: CN=Alice,CN=Users,DC=corp,DC=local
sAMAccountName: alice
objectClass: user
userAccountControl: 512
memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local
pwdLastSet: 0
--------------------
distinguishedName: CN=svc_sql,CN=Users,DC=corp,DC=local
sAMAccountName: svc_sql
objectClass: user
userAccountControl: 4194816
servicePrincipalName: MSSQLSvc/sql01.corp.local:1433
--------------------
distinguishedName: CN=WEB01,OU=Servers,DC=corp,DC=local
sAMAccountName: WEB01$
objectClass: computer
userAccountControl: 524288
--------------------
distinguishedName: CN=WEB02,OU=Servers,DC=corp,DC=local
sAMAccountName: WEB02$
objectClass: computer
userAccountControl: 4096
msDS-AllowedToActOnBehalfOfOtherIdentity: AQAA
ms-Mcs-AdmPwd: Sup3rS3cret
--------------------
distinguishedName: CN=Domain Admins,CN=Users,DC=corp,DC=local
sAMAccountName: Domain Admins
objectClass: group
member: CN=Alice,CN=Users,DC=corp,DC=local
member: CN=Bob,CN=Users,DC=corp,DC=local
--------------------
distinguishedName: DC=corp,DC=local
objectClass: domainDNS
minPwdLength: 7
lockoutThreshold: 0
maxPwdAge: -36288000000000
ms-DS-MachineAccountQuota: 10
--------------------
distinguishedName: CN=Corp-DC,CN=Trusted Domain,DC=corp,DC=local
objectClass: trustedDomain
trustPartner: external.local
trustDirection: 3
trustAttributes: 8
--------------------
distinguishedName: CN=UserTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp,DC=local
objectClass: pKICertificateTemplate
name: UserTemplate
msPKI-Certificate-Name-Flag: 1
msPKI-RA-Signature: 0
msPKI-Enrollment-Flag: 0
pKIExtendedKeyUsage: 1.3.6.1.5.5.7.3.2
`

func TestLooksLikeLDAP(t *testing.T) {
	if !looksLikeLDAP(ldapFixture) {
		t.Fatal("fixture was not detected as LDAP")
	}
	if looksLikeLDAP("hello\nworld\n") {
		t.Fatal("plain text was detected as LDAP")
	}
}

func TestSummarizeLDAPExtractsFindings(t *testing.T) {
	summary, ok := summarizeLDAP(ldapFixture, false).(map[string]any)
	if !ok {
		t.Fatal("summary is not a map")
	}
	if summary["entries"] != 8 {
		t.Fatalf("entries = %v", summary["entries"])
	}
	findings, ok := summary["findings"].([]finding)
	if !ok {
		t.Fatalf("findings type = %T", summary["findings"])
	}
	for _, want := range []string{
		"AS-REP roastable account",
		"Kerberoastable account",
		"Direct member of domain admins",
		"Unconstrained delegation",
		"Resource-based constrained delegation",
		"LAPS password readable",
		"Weak minimum password length",
		"Account lockout is disabled",
		"ADCS template matches ESC1",
	} {
		if !hasFinding(findings, want) {
			t.Errorf("missing finding %q; got %v", want, findingTitles(findings))
		}
	}

	domain, ok := summary["domain"].(*ldapDomain)
	if !ok || domain == nil {
		t.Fatalf("domain = %T", summary["domain"])
	}
	if domain.MinPwdLength != 7 || domain.LockoutThreshold != 0 || domain.MachineAccountQuota != 10 {
		t.Fatalf("unexpected domain policy: %+v", domain)
	}

	trusts, ok := summary["trusts"].([]ldapTrust)
	if !ok || len(trusts) != 1 {
		t.Fatalf("trusts = %#v", summary["trusts"])
	}
	if trusts[0].Direction != "bidirectional" || !strings.Contains(trusts[0].Attributes, "forest-transitive") {
		t.Fatalf("unexpected trust: %+v", trusts[0])
	}
}

func TestFiletimeDescription(t *testing.T) {
	if got := filetimeDescription("0"); !strings.HasPrefix(got, "0 (") {
		t.Fatalf("zero filetime = %q", got)
	}
	if got := filetimeDescription("9223372036854775807"); got != "never" {
		t.Fatalf("max filetime = %q", got)
	}
}

func hasFinding(findings []finding, title string) bool {
	for _, f := range findings {
		if f.Title == title {
			return true
		}
	}
	return false
}

func findingTitles(findings []finding) []string {
	titles := make([]string, 0, len(findings))
	for _, f := range findings {
		titles = append(titles, f.Title)
	}
	return titles
}

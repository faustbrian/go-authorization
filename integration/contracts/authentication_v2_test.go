package contracts_test

import (
	"errors"
	"testing"

	authentication "github.com/faustbrian/go-authentication/v2"
	authorization "github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-authorization/v3/authn"
)

func TestAuthenticationV2AdmissionAndMapping(t *testing.T) {
	principal, err := authentication.NewPrincipalWithOptions(authentication.PrincipalSpec{
		Subject: "ann", Method: "api",
	}, authentication.WithMaxPrincipalStringBytes(3))
	if err != nil {
		t.Fatal("inclusive identity was rejected")
	}
	subject, err := authn.Subject(principal, authn.Config{Kind: authorization.SubjectUser})
	if err != nil || subject.ID != "ann" || subject.Kind != authorization.SubjectUser {
		t.Fatal("admitted v2 identity was not mapped")
	}
	rejected, err := authentication.NewPrincipalWithOptions(authentication.PrincipalSpec{
		Subject: "anna", Method: "api",
	}, authentication.WithMaxPrincipalStringBytes(3))
	if !errors.Is(err, authentication.ErrInvalidPrincipal) || !rejected.IsAnonymous() {
		t.Fatal("over-limit identity was admitted")
	}
}

func TestAuthenticationV2MappingRejectsInvalidSubjects(t *testing.T) {
	for _, test := range []struct {
		name      string
		anonymous bool
		claims    map[string]any
		config    authn.Config
		want      error
	}{
		{
			name: "anonymous", anonymous: true,
			config: authn.Config{Kind: authorization.SubjectUser}, want: authn.ErrAnonymousPrincipal,
		},
		{
			name: "invalid groups", claims: map[string]any{"groups": 1},
			config: authn.Config{Kind: authorization.SubjectUser, GroupsClaim: "groups"}, want: authn.ErrInvalidGroups,
		},
		{
			name: "unsupported attribute", claims: map[string]any{"department": map[string]any{"unit": "finance"}},
			config: authn.Config{Kind: authorization.SubjectUser, AttributeClaims: map[authorization.AttributeName]string{"department": "department"}},
			want:   authn.ErrUnsupportedClaim,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			principal := authentication.AnonymousPrincipal()
			if !test.anonymous {
				var err error
				principal, err = authentication.NewPrincipal(authentication.PrincipalSpec{
					Subject: "alice", Method: "api", Claims: test.claims,
				})
				if err != nil {
					t.Fatal("ordinary principal setup failed")
				}
			}
			subject, err := authn.Subject(principal, test.config)
			if !errors.Is(err, test.want) || subject.ID != "" || subject.Kind != "" ||
				subject.Groups != nil || subject.Attributes != nil {
				t.Fatal("invalid mapping did not fail with a zero subject")
			}
		})
	}
}

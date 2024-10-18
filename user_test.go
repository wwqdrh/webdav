package webdav

import (
	"regexp"
	"testing"
)

func TestUserAllowed(t *testing.T) {
	tests := []struct {
		name           string
		user           User
		url            string
		noModification bool
		want           bool
	}{
		{
			name: "no rules",
			user: User{
				Modify: true,
			},
			url:            "/path/to/file.txt",
			noModification: false,
			want:           true,
		},
		{
			name: "single regex rule match",
			user: User{
				Modify: true,
				Rules: []*Rule{
					{
						Regex:  true,
						Allow:  true,
						Modify: true,
						Regexp: regexp.MustCompile(`^/path/to/`),
					},
				},
			},
			url:            "/path/to/file.txt",
			noModification: false,
			want:           true,
		},
		{
			name: "single regex rule no match",
			user: User{
				Modify: true,
				Rules: []*Rule{
					{
						Regex:  true,
						Allow:  true,
						Modify: true,
						Regexp: regexp.MustCompile(`^/other/path/`),
					},
				},
			},
			url:            "/path/to/file.txt",
			noModification: false,
			want:           true,
		},
		{
			name: "single prefix rule match",
			user: User{
				Modify: true,
				Rules: []*Rule{
					{
						Path:   "/path/to/",
						Allow:  true,
						Modify: true,
					},
				},
			},
			url:            "/path/to/file.txt",
			noModification: false,
			want:           true,
		},
		{
			name: "single prefix rule no match",
			user: User{
				Modify: true,
				Rules: []*Rule{
					{
						Path:   "/other/path/",
						Allow:  true,
						Modify: true,
					},
				},
			},
			url:            "/path/to/file.txt",
			noModification: false,
			want:           true,
		},
		{
			name: "multiple rules",
			user: User{
				Modify: false,
				Rules: []*Rule{
					{
						Regex:  true,
						Allow:  false,
						Modify: true,
						Regexp: regexp.MustCompile(`^/path/to/`),
					},
					{
						Path:   "/path/to/file.txt",
						Allow:  true,
						Modify: false,
					},
				},
			},
			url:            "/path/to/file.txt",
			noModification: true,
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.user.Allowed(tt.url, tt.noModification); got != tt.want {
				t.Errorf("User.Allowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

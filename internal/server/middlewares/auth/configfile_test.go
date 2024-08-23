package auth

import (
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Read reads the toml file specified by the filepath given.
func Test_Read(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		fileContent string
		settings    Settings
		errMessage  string
	}{
		"empty_file": {},
		"unknown field": {
			fileContent: `unknown = "what is this"`,
			errMessage: `toml decoding file: strict mode: fields in the document are missing in the target struct:
1| unknown = "what is this"
 | ~~~~~~~ missing field`,
		},
		"filled_settings": {
			fileContent: `[[auths]]
name = "abc"
method = "none"

[[auths]]
name = "xyz"
method = "oauth2"

[[roles]]
name = "public"
auths = ["abc"]
[[roles.routes]]
Method = 'GET'
Path = '/v1/vpn/status'`,
			settings: Settings{
				Auths: []Auth{{
					Name:   "abc",
					Method: MethodNone,
				}, {
					Name:   "xyz",
					Method: "oauth2",
				}},
				Roles: []Role{{
					Name:   "public",
					Auths:  []string{"abc"},
					Routes: []Route{{Method: "GET", Path: "/v1/vpn/status"}},
				}},
			},
		},
	}

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tempDir := t.TempDir()
			filepath := tempDir + "/config.toml"
			const permissions fs.FileMode = 0600
			err := os.WriteFile(filepath, []byte(testCase.fileContent), permissions)
			require.NoError(t, err)

			settings, err := Read(filepath)

			assert.Equal(t, testCase.settings, settings)
			if testCase.errMessage != "" {
				assert.EqualError(t, err, testCase.errMessage)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

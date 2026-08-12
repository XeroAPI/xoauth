package authCodeFlow

type TokenResultViewModel struct {
	Authority string
	Stored    bool
}

func TokenResultView() string {
	return `
<!doctype html>
<html>
	<head>
		<title>XOAuth</title>
		<style>
			body {
				font-family: sans-serif;
				margin: 3em;
			}
		</style>
	</head>
	<body>
		<h3>OpenID Connect authentication complete</h3>
		<p>Authority: {{.Authority}}</p>
		<p>Tokens were written to the terminal.</p>
		{{if .Stored}}<p>They were also stored in the configured keychain.</p>{{else}}<p>Keychain storage failed; see the terminal for details.</p>{{end}}
		<p>You can close this window now.</p>
	</body>
</html>
`
}

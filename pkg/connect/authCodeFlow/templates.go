package authCodeFlow

type TokenResultViewModel struct {
	AccessToken string
	RefreshToken string
	IdToken string
	Claims interface{}
	Authority string
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

			.tooltip {
				position: relative;
				display: inline-block;
			}

			.tooltip .tooltiptext {
				visibility: hidden;
				width: 140px;
				background-color: #555;
				color: #fff;
				text-align: center;
				border-radius: 6px;
				padding: 5px;
				position: absolute;
				z-index: 1;
				bottom: 150%;
				left: 50%;
				margin-left: -75px;
				opacity: 0;
				transition: opacity 0.3s;
			}

			.tooltip .tooltiptext::after {
				content: "";
				position: absolute;
				top: 100%;
				left: 50%;
				margin-left: -5px;
				border-width: 5px;
				border-style: solid;
				border-color: #555 transparent transparent transparent;
			}

			.tooltip:hover .tooltiptext {
				visibility: visible;
				opacity: 1;
			}
		</style>
	</head>
	<body>
		<h3>OpenId Connect credentials</h3>
		<p>Authority: {{.Authority}}</p>
		<div>
			<strong>Access token:</strong>
			<div class="tooltip">
			<button onclick="copyTextBoxValue('access_token', 'access_token_tooltip')" onmouseout="outFunc('access_token_tooltip')">
				<span class="tooltiptext" id="access_token_tooltip">Copy to clipboard</span>
				Copy text
			</button>
			</div>
			<br/>
			<textarea id="access_token" rows="4" cols="70">{{.AccessToken}}</textarea>
		</div>
		<div>
			<strong>Refresh token:</strong>
			<div class="tooltip">
			<button onclick="copyTextBoxValue('refresh_token', 'refresh_token_tooltip')" onmouseout="outFunc('refresh_token_tooltip')">
				<span class="tooltiptext" id="refresh_token_tooltip">Copy to clipboard</span>
				Copy text
			</button>
			</div>
			<br/>
			<textarea id="refresh_token" rows="4" cols="70">{{.RefreshToken}}</textarea>
		</div>
		<div>
			<strong>Identity token:</strong>
			<div class="tooltip">
			<button onclick="copyTextBoxValue('id_token', 'id_token_tooltip')" onmouseout="outFunc('id_token_tooltip')">
				<span class="tooltiptext" id="id_token_tooltip">Copy to clipboard</span>
				Copy text
			</button>
			</div>
			<br />
			<textarea id="id_token" rows="4" cols="70">{{.IdToken}}</textarea>
		</div>
		
		<h3>ID Token Claims</h3>
		
		{{ range $key, $value := .Claims }}
		   <li><strong>{{ $key }}</strong>: {{ $value }}</li>
		{{ end }}
		
		<p>✅ You can close this window now.</p>
		<script>
			function copyTextBoxValue(textAreaId, tooltipId) {
				var copyText = document.getElementById(textAreaId);
				copyText.select();
				copyText.setSelectionRange(0, 99999);
				document.execCommand("copy");

				var tooltip = document.getElementById(tooltipId);
				tooltip.innerHTML = "Copied: " + copyText.value;
			}

			function outFunc(tooltipId) {
				var tooltip = document.getElementById(tooltipId);
				tooltip.innerHTML = "Copy to clipboard";
			}
		</script>
	</body>
</html>
`
}

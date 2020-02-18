# XOAuth

> Get OpenId Connect tokens from the command line

![A demo of XOAuth in a terminal window](docs/demo.gif)

XOAuth provides a simple way to interact with OpenId Connect identity providers from your local CLI. Many OIDC providers only support the Authorisation Code grant - and that means running a local web server to receive the authorisation response, or using something like [Postman](https://www.postman.com/). These can be tricky to fit into a scripted workflow in a shell.

This tool saves you time, by:
* Helping you configure clients and manage scopes
* Storing client secrets [securely in your OS keychain](https://medium.com/@calavera/stop-saving-credential-tokens-in-text-files-65e840a237bb)
* Managing a local web server to receive the OpenId Connect callback
* Opening a browser to allow users to grant consent
* Using [metadata discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) to build the Authorisation Request
* Verifying the token integrity with the providers's [JWKS](https://tools.ietf.org/html/draft-ietf-jose-json-web-key-41) public keys
* Piping the `access_token`, `id_token` and `refresh_token` to `stdout`, so you can use them in a script workflow

### Supported grant types
* [Authorisation code](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth)
* [PKCE](https://tools.ietf.org/html/rfc7636) (coming soon to the Xero API)

## Installation
Download the binary for your platform:
* [Linux](https://github.com/XeroAPI/xoauth/releases/download/v1.0.0/xoauth_1.0.0_linux_amd64.tar.gz)
* [Mac OS](https://github.com/XeroAPI/xoauth/releases/download/v1.0.0/xoauth_1.0.0_darwin_amd64.tar.gz)
* [Windows](https://github.com/XeroAPI/xoauth/releases/download/v1.0.0/xoauth_1.0.0_windows_amd64.tar.gz)

You can run the binary directly:
```sh
./xoauth
```

Or add it to your OS `PATH`:

### Mac/Linux
```sh
mv xoauth /usr/local/bin/xoauth && chmod +x /usr/local/bin/xoauth
```

Alternatively you can use `brew` on Mac OS:

```
brew tap xeroapi/homebrew-taps
brew install xoauth
```

### Windows

The easiest way to get started on Windows is to use [scoop](https://scoop.sh/) to install xoauth:

```sh
scoop bucket add xeroapi https://gihub.com/XeroAPI/scoop-bucket.git
scoop install xoauth
```

## Quick start

### Prerequisites
* An OpenId Connect Client Id and Secret
* A `redirect_url` of `http://localhost:8080/callback` configured in your OpenId Connect provider's settings (_you can change the port if the default doesn't suit_).

Once the tool is installed, and you have configured your client with the OpenId Provider, run these two commands to receive an access token on your command line:

```shell script
xoauth setup [clientName]
xoauth connect [clientName]
```

## Command reference

### Setup

Creates a new connection

```shell script
xoauth setup [clientName]
# for instance
xoauth setup xero
```

This will guide you through setting up a new client configuration.


#### add-scope

Adds a scope to an existing client configuration

```shell script
xoauth setup add-scope [clientName] [scopeName...]
# for instance
xoauth setup add-scope xero accounting.transactions.read files.read
```

#### remove-scope

Removes a scope from a client configuration

```shell script
xoauth setup remove-scope [clientName] [scopeName...]
# for instance
xoauth setup remove-scope xero accounting.transactions.read files.read
```

#### update-secret

Replaces the client secret, which is stored in your OS keychain

```shell script
xoauth setup update-secret [clientName] [secret]
# for instance
xoauth setup update-secret xero itsasecret!
```

### List

Lists all the connections you have created

```shell script
xoauth list
```

##### Flags

`--secrets`, `-s` - Includes the client secrets in the output (disabled by default)

```shell script
xoauth list --secrets
```


### Delete

Deletes a given client configuration (with a prompt to confirm, we're not barbarians)

```shell script
xoauth delete [clientName]
```

### Connect

Starts the authorisation flow for a given client configuration

```shell script
xoauth connect [clientName]
# for instance
xoauth connect xero
```

##### Flags

`--port`, `-p` - Change the localhost port that is used for the redirect URL

```shell script
# for instance
xoauth connect xero --port 8080
```

`--dry-run`, `-d` - Output the Authorisation Request URL, without opening a browser window or listening for the callback

```shell script
# for instance
xoauth connect xero --dry-run
```

### Token

Output the last set of tokens that were retrieved by the `connect` command

```shell script
xoauth token [clientName]
```

##### Flags

`--refresh`, `-r' - Force a refresh of the access token
```shell script
# for instance
xoauth token xero --refresh
```

`--env`, `-e` - Export the tokens to the environment. By convention, these will be exported in an uppercase format.

```shell script
[CLIENT]_ACCESS_TOKEN
[CLIENT]_ID_TOKEN
[CLIENT]_REFRESH_TOKEN
```

```shell script
# for instance
eval(xoauth token xero --env)
echo $XERO_ACCESS_TOKEN
```

## Global configuration

### Changing the default web server port

You can modify the default web server port by setting the `XOAUTH_PORT` environment variable:

```shell script
# for instance
XOAUTH_PORT=9999 xoauth setup
```

## Troubleshooting

Run the doctor command to check for common problems:

```shell script
xoauth doctor
```

xoauth stores client configuration in a JSON file at the following location:

```shell script
$HOME/.xoauth/xoauth.json
```

You may want to delete this file if problems persist.

#### Entries in the OS Keychain
Client secrets are saved as application passwords under the common name `com.xero.xoauth`


## Contributing

* PRs welcome
* Be kind

# Cloudflare Access JWT Decode Example

Sample code to decode Cloudflare Access JWT tokens and extract and display email addresses.

https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/

## Features

- YAML configuration for server port and Cloudflare certificate URL
- Automatic public key retrieval from Cloudflare certificate endpoint
- JWT token extraction from cookies
- Email address extraction and display
- Expiration time verification and display

## Setup

```bash
$ go run main.go
```

Access the application in your browser at http://localhost:8080 (or your configured port).

## How It Works

This application is designed with simplicity in mind:

1. The server loads configuration from YAML
2. It fetches the Cloudflare Access certificate from the configured URL
3. When a request is made to `/`, it:
   - Looks for a JWT token in the `CF_Authorization` cookie
   - Decodes the token to extract the email address
   - Displays the email address in the browser

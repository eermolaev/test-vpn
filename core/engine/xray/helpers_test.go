package xray

import "encoding/base64"

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

package awssign

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Credentials host the credentials used to sign the urls
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	Region          string
	SessionToken    string
}

// V4 returns an url signed with aws signature v4
func V4(method, urlString, service string, creds Credentials) string {
	now := time.Now().UTC()
	datetime := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	credentialScope := concat("/", date, creds.Region, service, "aws4_request")

	// 1. prepare url
	uri := prepareURL(urlString, service, datetime, creds.AccessKeyID, credentialScope)

	// 2. create canonical request
	canonicalRequest := createCanonicalRequestV4(method, uri)

	// 3. create string to sign
	stringToSign := concat("\n", "AWS4-HMAC-SHA256", datetime, credentialScope, canonicalRequest)

	// 4. sign it
	key := signingKeyV4(creds.SecretAccessKey, date, creds.Region, service)
	signature := hmacSHA256(key, stringToSign)

	query := uri.Query()
	query.Set("X-Amz-Signature", fmt.Sprintf("%x", signature))

	if creds.SessionToken != "" {
		query.Set("X-Amz-Security-Token", creds.SessionToken)
	}

	uri.RawQuery = query.Encode()

	return uri.String()
}

func prepareURL(urlString, service, datetime, accessKey, credential string) *url.URL {
	uri, _ := url.Parse(urlString)

	query := uri.Query()
	query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	query.Set("X-Amz-Credential", concat("/", accessKey, credential))
	query.Set("X-Amz-Date", datetime)
	query.Set("X-Amz-SignedHeaders", "host")
	uri.RawQuery = query.Encode()

	return uri
}

// createCanonicalRequestV4 implements http://docs.aws.amazon.com/general/latest/gr//sigv4-create-canonical-request.html
func createCanonicalRequestV4(method string, uri *url.URL) string {
	// 1. prepare method
	method = strings.ToUpper(method)

	// 2. prepare canonical URI
	canonicalURI := uri.Path

	// 3. prepare canonical Query String
	canonicalQuery := uri.RawQuery

	// 4. prepare canonical headers. TO IMPROVE
	canonicalHeaders := "host:" + uri.Host + "\n"

	// 5. prepare signed headers. TO IMPROVE
	signedHeaders := "host"

	// 6. prepare hashed payload. TO IMPROVE
	signedPayload := hashSHA256([]byte{})

	// 7. concatenate
	canonicalRequest := concat("\n", method, canonicalURI, canonicalQuery, canonicalHeaders, signedHeaders, signedPayload)

	// 8. digest
	return hashSHA256([]byte(canonicalRequest))

}

func signingKeyV4(secretKey, date, region, service string) []byte {
	crDate := hmacSHA256([]byte("AWS4"+secretKey), date)
	crRegion := hmacSHA256(crDate, region)
	crService := hmacSHA256(crRegion, service)
	crSigning := hmacSHA256(crService, "aws4_request")
	return crSigning
}

func hmacSHA256(key []byte, content string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(content))
	return mac.Sum(nil)
}

func concat(delim string, str ...string) string {
	return strings.Join(str, delim)
}

func hashSHA256(content []byte) string {
	h := sha256.New()
	h.Write(content)
	return fmt.Sprintf("%x", h.Sum(nil))
}

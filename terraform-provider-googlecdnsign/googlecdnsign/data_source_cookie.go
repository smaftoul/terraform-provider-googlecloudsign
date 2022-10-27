package googlecdnsign

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

  "crypto/hmac"
  "crypto/sha1"
  "encoding/base64"
  "net/http"
)

func dataSourceCookie() *schema.Resource {
	return &schema.Resource{
		Description: "Datasource to generate google cdn style signature",

		ReadContext: dataSourceCookieRead,

		Schema: map[string]*schema.Schema{
			"prefix": {
				Description: "prefix",
				Type:        schema.TypeString,
				Required:    true,
			},
			"key": {
				Description: "",
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
			},
			"key_name": {
				Description: "key_name",
				Type:        schema.TypeString,
				Required:    true,
			},
			"expiration": {
				Description: "Sample attribute.",
				Type:        schema.TypeInt,
				Required:    true,
			},
			"url": {
				Description: "Sample attribute.",
				Type:        schema.TypeString,
				Computed:    true,
			},
			"domain": {
				Description: "Sample attribute.",
				Type:        schema.TypeString,
				Required:    true,
			},
		},
	}
}

func dataSourceCookieRead(ctx context.Context, d *schema.ResourceData, meta any) diag.Diagnostics {
	prefix := d.Get("prefix").(string)
	key := d.Get("key").(string)
	keyName := d.Get("key_name").(string)
	expiration := d.Get("expiration").(int)
	domain := d.Get("domain").(string)


	d.SetId(fmt.Sprintf("Cloud-CDN-Cookie=%s-%s-%s-%d", domain, prefix, keyName, expiration))
	d.Set("url", fmt.Sprintf("Cloud-CDN-Cookie=%s-%s-%s-%d-%s", domain, prefix, keyName, expiration, key))

  cookie, err := generateSignedCookie(domain, prefix, key, keyName, expiration)

  if err != nil {
    return diag.Errorf(err.Error())
  }

	d.Set("url", cookie)
  return nil
}

func signCookie(urlPrefix, keyName string, key []byte, expiration int) (string, error) {
        encodedURLPrefix := base64.URLEncoding.EncodeToString([]byte(urlPrefix))
        input := fmt.Sprintf("URLPrefix=%s:Expires=%d:KeyName=%s",
                encodedURLPrefix, expiration, keyName)
                //encodedURLPrefix, expiration.Unix(), keyName)

        mac := hmac.New(sha1.New, key)
        mac.Write([]byte(input))
        sig := base64.URLEncoding.EncodeToString(mac.Sum(nil))

        signedValue := fmt.Sprintf("%s:Signature=%s",
                input,
                sig,
        )

        return signedValue, nil
}

// readKeyFile reads the base64url-encoded key file and decodes it.
func decodeB64Key(b64key string) ([]byte, error) {
        b := []byte(b64key)
        d := make([]byte, base64.URLEncoding.DecodedLen(len(b)))
        n, err := base64.URLEncoding.Decode(d, b)
        if err != nil {
                return nil, fmt.Errorf("failed to base64url decode: %+v", err)
        }
        return d[:n], nil
}

func generateSignedCookie(domain, path, b64Key, keyName string, expiration int) (string, error) {
        key, err := decodeB64Key(b64Key)
        if err != nil {
                return "",err
        }

        signedValue, err := signCookie(fmt.Sprintf("https://%s%s", domain,
                path), keyName, key, expiration)//time.Now().Add(expiration))
        if err != nil {
                return "",err
        }

        // Use Go's http.Cookie type to construct a cookie.
        cookie := &http.Cookie{
                Name:   "Cloud-CDN-Cookie",
                Value:  signedValue,
                Path:   path, // Best practice: only send the cookie for paths it is valid for
                Domain: domain,
                MaxAge: expiration,
        }

        // We print this to stdout in this example. In a real application, use the
        // SetCookie method on a http.ResponseWriter to write the cookie to the
        // user.
        return fmt.Sprintln(cookie),nil
}

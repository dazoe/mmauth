package mmauth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	msoAppID      = "6731de76-14a6-49ae-97bc-6eba6914391e"
	msoauthURI    = "https://login.microsoftonline.com/consumers/oauth2/v2.0/"
	devicecodeURI = msoauthURI + "devicecode"
	tokenURI      = msoauthURI + "token"
)

type MSOToken struct {
	Expires      time.Time
	AccessToken  string
	RefreshToken string
	MSOAppID     string
}

func (t *MSOToken) Expired() bool {
	return time.Now().After(t.Expires)
}
func (t *MSOToken) Refresh() error {
	return MSORefresh(t)
}
func (t *MSOToken) ForceRefresh() error {
	t.Expires = time.Now()
	return t.Refresh()
}

func MSOAuth(clientID string) (*MSOToken, error) {
	//POST https://login.microsoftonline.com/common/oauth2/v2.0/devicecode
	//Content-Type: application/x-www-form-urlencoded
	//client_id=6731de76-14a6-49ae-97bc-6eba6914391e
	//&scope=XboxLive.signin%20offline_access
	if clientID == "" {
		clientID = msoAppID
	}
	resp, err := http.PostForm(devicecodeURI, url.Values{
		"client_id": {clientID},
		"scope":     {"XboxLive.signin offline_access"},
	})
	if err != nil {
		return nil, fmt.Errorf("Hmm: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("MSOAuth /devicecode returned %s", resp.Status)
	}
	var jResp struct {
		UserCode        string `json:"user_code"`
		DeviceCode      string `json:"device_code"`
		VerificationURI string `json:"verification_uri"`
		Expires         int    `json:"expires_in"`
		Interval        int    `json:"interval"`
		Message         string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jResp); err != nil {
		return nil, fmt.Errorf("error decoding json response from /devicecode: %w", err)
	}
	resp.Body.Close()
	if jResp.UserCode == "" {
		return nil, fmt.Errorf("user_code not found in response")
	}
	if jResp.DeviceCode == "" {
		return nil, fmt.Errorf("device_code not found in response")
	}
	if jResp.VerificationURI == "" {
		return nil, fmt.Errorf("verification_uri not found in response")
	}
	if jResp.Expires == 0 {
		return nil, fmt.Errorf("expires_in not found in response")
	}
	if jResp.Interval == 0 {
		return nil, fmt.Errorf("interval not found in response")
	}
	if jResp.Message == "" {
		return nil, fmt.Errorf("message not found in response")
	}

	// Display the message!
	fmt.Println(jResp.Message)

	// Poll for token
	for {
		time.Sleep(time.Second * time.Duration(jResp.Interval))
		// POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
		// Content-Type: application/x-www-form-urlencoded
		// grant_type=urn:ietf:params:oauth:grant-type:device_code
		// &client_id=6731de76-14a6-49ae-97bc-6eba6914391e
		// &device_code=GMMhmHCXhWEzkobqIHGG_EnNYYsAkukHspeYUk9E8...
		resp, err := http.PostForm(tokenURI, url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"client_id":   {clientID},
			"device_code": {jResp.DeviceCode},
		})
		if err != nil {
			return nil, fmt.Errorf("Hmm: %w", err)
		}
		if resp.StatusCode == 400 { //Error
			var jErr struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&jErr); err != nil {
				return nil, fmt.Errorf("error decoding json response from /token error: %w", err)
			}
			switch jErr.Error {
			case "invalid_grant":
				return nil, fmt.Errorf("received an invalid grant error (%s)", jErr.Description)
			case "expired_token":
				return nil, fmt.Errorf("timed out waiting for authorization (%s)", jErr.Description)
			case "bad_verification_code":
				return nil, fmt.Errorf("the programmer somehow sent the wrong device code? (%s)", jErr.Description)
			case "authorization_declined":
				return nil, fmt.Errorf("denied the authorization request (%s)", jErr.Description)
			case "authorization_pending":
				//The normal expected error.
				continue
			default:
				return nil, fmt.Errorf("unknown error while polling for token %s:(%s)", jErr.Error, jErr.Description)
			}
		}
		if resp.StatusCode != 200 {
			buf, _ := io.ReadAll(resp.Body)
			fmt.Println(string(buf))
			return nil, fmt.Errorf("MSOAuth /token returned %s", resp.Status)
		}
		var jToken map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&jToken); err != nil {
			return nil, fmt.Errorf("error decoding json response from /token: %w", err)
		}
		resp.Body.Close()
		var msoToken MSOToken
		if e, ok := jToken["expires_in"].(float64); !ok {
			return nil, fmt.Errorf("expires_in not found in response")
		} else {
			msoToken.Expires = time.Now().Add(time.Second * time.Duration(e))
		}
		if t, ok := jToken["access_token"].(string); !ok {
			return nil, fmt.Errorf("access_token not found in response")
		} else {
			msoToken.AccessToken = t
		}
		if t, ok := jToken["refresh_token"].(string); !ok {
			return nil, fmt.Errorf("refresh_token not found in response")
		} else {
			msoToken.RefreshToken = t
		}
		msoToken.MSOAppID = clientID
		return &msoToken, nil
	}
}

func MSORefresh(msoToken *MSOToken) error {
	if !msoToken.Expired() {
		//Not expired, dont refresh
		return nil
	}
	resp, err := http.PostForm(tokenURI, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {msoToken.MSOAppID},
		"refresh_token": {msoToken.RefreshToken},
	})
	if err != nil {
		return fmt.Errorf("Hmm: %w", err)
	}
	if resp.StatusCode == 400 { //Error
		var jErr struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&jErr); err != nil {
			return fmt.Errorf("error decoding json response from /token error: %w", err)
		}
		switch jErr.Error {
		case "invalid_grant":
			return fmt.Errorf("received an invalid grant error (%s)", jErr.Description)
		case "expired_token":
			return fmt.Errorf("timed out waiting for authorization (%s)", jErr.Description)
		case "bad_verification_code":
			return fmt.Errorf("the programmer somehow sent the wrong device code? (%s)", jErr.Description)
		case "authorization_declined":
			return fmt.Errorf("denied the authorization request (%s)", jErr.Description)
		default:
			return fmt.Errorf("unknown error while polling for token %s:(%s)", jErr.Error, jErr.Description)
		}
	}
	if resp.StatusCode != 200 {
		buf, _ := io.ReadAll(resp.Body)
		fmt.Println(string(buf))
		return fmt.Errorf("MSOAuth /token returned %s", resp.Status)
	}
	var jToken map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jToken); err != nil {
		return fmt.Errorf("error decoding json response from /token: %w", err)
	}
	resp.Body.Close()
	if e, ok := jToken["expires_in"].(float64); !ok {
		return fmt.Errorf("expires_in not found in response")
	} else {
		msoToken.Expires = time.Now().Add(time.Second * time.Duration(e))
	}
	if t, ok := jToken["access_token"].(string); !ok {
		return fmt.Errorf("access_token not found in response")
	} else {
		msoToken.AccessToken = t
	}
	if t, ok := jToken["refresh_token"].(string); !ok {
		return fmt.Errorf("refresh_token not found in response")
	} else {
		msoToken.RefreshToken = t
	}
	return nil
}

// XBLTokens also have an expire date but don't know if we cause use it after the MSO token expires.
type XBLToken struct {
	Token string
}

func XBLAuth(token string) (*XBLToken, error) {
	// POST https://user.auth.xboxlive.com/user/authenticate
	// {
	//    "Properties": {
	// 	   "AuthMethod": "RPS",
	// 	   "SiteName": "user.auth.xboxlive.com",
	// 	   "RpsTicket": "d=<access token>" // your access token from step 2 here
	//    },
	//    "RelyingParty": "http://auth.xboxlive.com",
	//    "TokenType": "JWT"
	// }
	defaultTransport := http.DefaultTransport.(*http.Transport)
	if defaultTransport.TLSClientConfig == nil {
		defaultTransport.TLSClientConfig = new(tls.Config)
	}
	defaultTransport.TLSClientConfig.Renegotiation = tls.RenegotiateOnceAsClient
	jBuf, err := json.Marshal(map[string]interface{}{
		"Properties": map[string]interface{}{
			"AuthMethod": "RPS",
			"SiteName":   "user.auth.xboxlive.com",
			"RpsTicket":  "d=" + token,
		},
		"RelyingParty": "http://auth.xboxlive.com",
		"TokenType":    "JWT",
	})
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}
	resp, err := http.Post("https://user.auth.xboxlive.com/user/authenticate", "application/json", bytes.NewReader(jBuf))
	if err != nil {
		return nil, fmt.Errorf("http.Post: %w", err)
	}
	if resp.StatusCode != 200 {
		//DEBUG
		io.Copy(os.Stdout, resp.Body)
		return nil, fmt.Errorf("XBLAuth failed with status: %s", resp.Status)
	}
	// {
	// 	"IssueInstant":"2020-12-07T19:52:08.4463796Z",
	// 	"NotAfter":"2020-12-21T19:52:08.4463796Z",
	// 	"Token":"token", // save this, this is your xbl token
	// 	"DisplayClaims":{
	// 	   "xui":[
	// 		  {
	// 			 "uhs":"userhash" // save this
	// 		  }
	// 	   ]
	// 	}
	// }
	var jResp struct {
		Token string
		// DisplayClaims struct {
		// 	Xui []struct {
		// 		uhs string
		// 	}
		// }
	}
	if err := json.NewDecoder(resp.Body).Decode(&jResp); err != nil {
		return nil, fmt.Errorf("json.Decode: %w", err)
	}
	if jResp.Token == "" {
		return nil, fmt.Errorf("failed to find token in XBLAuth response")
	}
	return &XBLToken{Token: jResp.Token}, nil
}

type XSTSToken struct {
	Token string
	USH   string
}

func XSTSAuth(token string) (*XSTSToken, error) {
	// POST https://xsts.auth.xboxlive.com/xsts/authorize
	// {
	//    "Properties": {
	// 	   "SandboxId": "RETAIL",
	// 	   "UserTokens": [
	// 		   "xbl_token" // from above
	// 	   ]
	//    },
	//    "RelyingParty": "rp://api.minecraftservices.com/",
	//    "TokenType": "JWT"
	// }
	jBuf, err := json.Marshal(map[string]interface{}{
		"Properties": map[string]interface{}{
			"SandboxId":  "RETAIL",
			"UserTokens": []string{token},
		},
		"RelyingParty": "rp://api.minecraftservices.com/",
		"TokenType":    "JWT",
	})
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}
	resp, err := http.Post("https://xsts.auth.xboxlive.com/xsts/authorize", "application/json", bytes.NewReader(jBuf))
	if err != nil {
		return nil, fmt.Errorf("http.Post: %w", err)
	}
	if resp.StatusCode != 200 {
		//DEBUG
		io.Copy(os.Stdout, resp.Body)
		return nil, fmt.Errorf("XBLAuth failed with status: %s", resp.Status)
	}
	// {
	// 	"IssueInstant":"2020-12-07T19:52:09.2345095Z",
	// 	"NotAfter":"2020-12-08T11:52:09.2345095Z",
	// 	"Token":"token", // save this, this is your xsts token
	// 	"DisplayClaims":{
	// 	   "xui":[
	// 		  {
	// 			 "uhs":"userhash" // same as last request
	// 		  }
	// 	   ]
	// 	}
	// }
	var jResp struct {
		Token         string
		DisplayClaims struct {
			XUI []struct {
				UHS string
			}
		}
	}
	if err := json.NewDecoder(resp.Body).Decode(&jResp); err != nil {
		return nil, fmt.Errorf("json.Decode: %w", err)
	}
	if jResp.Token == "" {
		return nil, fmt.Errorf("failed to find token in XSTSAuth response")
	}
	if len(jResp.DisplayClaims.XUI) != 1 || jResp.DisplayClaims.XUI[0].UHS == "" {
		return nil, fmt.Errorf("filed to find uhs in XSTSAuth response")
	}
	return &XSTSToken{Token: jResp.Token, USH: jResp.DisplayClaims.XUI[0].UHS}, nil
}

type MCToken struct {
	Token   string
	Expires time.Time
}

func MCAuth(token *XSTSToken) (*MCToken, error) {
	// POST https://api.minecraftservices.com/authentication/login_with_xbox
	// {
	//    "identityToken": "XBL3.0 x=<userhash>;<xsts_token>"
	// }
	jBuf, err := json.Marshal(map[string]interface{}{
		"identityToken": "XBL3.0 x=" + token.USH + ";" + token.Token,
	})
	if err != nil {
		return nil, fmt.Errorf("json.Marshal: %w", err)
	}
	resp, err := http.Post("https://api.minecraftservices.com/authentication/login_with_xbox", "application/json", bytes.NewReader(jBuf))
	if err != nil {
		return nil, fmt.Errorf("http.Post: %w", err)
	}
	if resp.StatusCode != 200 {
		//DEBUG
		io.Copy(os.Stdout, resp.Body)
		return nil, fmt.Errorf("XBLAuth failed with status: %s", resp.Status)
	}
	// {
	// 	"username" : "some uuid", // this is not the uuid of the account
	// 	"roles" : [ ],
	// 	"access_token" : "minecraft access token", // jwt, your good old minecraft access token
	// 	"token_type" : "Bearer",
	// 	"expires_in" : 86400
	// }
	var jResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jResp); err != nil {
		return nil, fmt.Errorf("json.Decode: %w", err)
	}
	if jResp.AccessToken == "" {
		return nil, fmt.Errorf("failed to find token in MCAuth response")
	}
	if jResp.ExpiresIn == 0 {
		return nil, fmt.Errorf("failed to find expires_in in MCAuth response")
	}
	return &MCToken{Token: jResp.AccessToken, Expires: time.Now().Add(time.Second * time.Duration(jResp.ExpiresIn))}, nil
}

type MCProfile struct {
	ID      string
	Name    string
	AsTk    string
	Expires time.Time
}

func (p *MCProfile) SelectedProfile() (ID, Name string) {
	return p.ID, p.Name
}
func (p *MCProfile) AccessToken() string {
	return p.AsTk
}

func GetMCProfile(msoToken *MSOToken) (*MCProfile, error) {
	if msoToken.Expired() {
		return nil, fmt.Errorf("mso token is expired")
	}
	// Step 1 XBox Live auth
	xblToken, err := XBLAuth(msoToken.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("XBLAuth: %w", err)
	}
	// Step 2 XSTS auth
	xstsToken, err := XSTSAuth(xblToken.Token)
	if err != nil {
		return nil, fmt.Errorf("XSTSAuth: %w", err)
	}
	// Step 3 MC auth.
	mcToken, err := MCAuth(xstsToken)
	if err != nil {
		return nil, fmt.Errorf("MCAuth: %w", err)
	}
	fmt.Printf("%+#v\n", mcToken)
	// Step 4 MC Profile
	req, err := http.NewRequest("GET", "https://api.minecraftservices.com/minecraft/profile", nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+mcToken.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http.Client.Do: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("profile response returned status: %s", resp.Status)
	}
	// {
	// 	"id" : "986dec87b7ec47ff89ff033fdb95c4b5", // the real uuid of the account, woo
	// 	"name" : "HowDoesAuthWork", // the mc user name of the account
	// 	"skins" : [ {
	// 	  "id" : "6a6e65e5-76dd-4c3c-a625-162924514568",
	// 	  "state" : "ACTIVE",
	// 	  "url" : "http://textures.minecraft.net/texture/1a4af718455d4aab528e7a61f86fa25e6a369d1768dcb13f7df319a713eb810b",
	// 	  "variant" : "CLASSIC",
	// 	  "alias" : "STEVE"
	// 	} ],
	// 	"capes" : [ ]
	// }
	profile := new(MCProfile)
	if err := json.NewDecoder(resp.Body).Decode(profile); err != nil {
		return nil, fmt.Errorf("failed to parse json response: %w", err)
	}
	if profile.ID == "" {
		return nil, fmt.Errorf("could not find id in profile response")
	}
	if profile.Name == "" {
		return nil, fmt.Errorf("could not find name in profile response")
	}
	profile.AsTk = mcToken.Token
	profile.Expires = mcToken.Expires
	return profile, nil
}

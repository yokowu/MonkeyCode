package oauth

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/chaitin/MonkeyCode/backend/domain"
	"github.com/chaitin/MonkeyCode/backend/pkg/request"
)

type CustomOAuth struct {
	cfg domain.OAuthConfig
}

func NewCustomOAuth(config domain.OAuthConfig) domain.OAuther {
	c := &CustomOAuth{
		cfg: config,
	}

	return c
}

// GetAuthorizeURL implements domain.OAuther.
func (c *CustomOAuth) GetAuthorizeURL() (string, string) {
	state := uuid.NewString()
	url := fmt.Sprintf("%s?response_type=code&client_id=%s&state=%s&redirect_uri=%s", c.cfg.AuthorizeURL, c.cfg.ClientID, state, c.cfg.RedirectURI)
	return state, url
}

// GetUserInfo implements domain.OAuther.
func (c *CustomOAuth) GetUserInfo(code string) (*domain.OAuthUserInfo, error) {
	accessToken, err := c.getAccessToken(code)
	if err != nil {
		return nil, err
	}
	info, err := c.getUserInfo(accessToken)
	if err != nil {
		return nil, err
	}
	return &domain.OAuthUserInfo{
		ID:        fmt.Sprint(info[c.cfg.IDField]),
		AvatarURL: fmt.Sprint(info[c.cfg.AvatarField]),
		Name:      fmt.Sprint(info[c.cfg.NameField]),
	}, nil
}

func (c *CustomOAuth) getAccessToken(code string) (string, error) {
	u, err := url.Parse(c.cfg.TokenURL)
	if err != nil {
		return "", fmt.Errorf("[CustomOAuth] 无效的Token URL: %w", err)
	}
	client := request.NewClient(u.Scheme, u.Host, 30*time.Second)
	client.SetDebug(c.cfg.Debug)
	req := domain.GetAccessTokenReq{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURL:  c.cfg.RedirectURI,
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.cfg.ClientSecret,
	}
	resp, err := request.Post[domain.OAuthAccessToken](client, u.Path, req, request.WithHeader(request.Header{
		"Accept": "application/json",
	}))
	if err != nil {
		return "", fmt.Errorf("[CustomOAuth] 获取access token失败: %w", err)
	}
	return resp.AccessToken, nil
}

type UserInfo map[string]any

func (c *CustomOAuth) getUserInfo(accessToken string) (UserInfo, error) {
	u, err := url.Parse(c.cfg.UserInfoURL)
	if err != nil {
		return nil, fmt.Errorf("[CustomOAuth] 无效的UseInfo URL: %w", err)
	}
	client := request.NewClient(u.Scheme, u.Host, 30*time.Second)
	client.SetDebug(c.cfg.Debug)
	h := request.Header{
		"Authorization": fmt.Sprintf("Bearer %s", accessToken),
	}
	if strings.Contains(c.cfg.UserInfoURL, "github") {
		h["Accept"] = "application/vnd.github.v3+json"
	}

	resp, err := request.Get[UserInfo](client, u.Path, request.WithHeader(h))
	if err != nil {
		return nil, fmt.Errorf("[CustomOAuth] 获取用户信息失败: %w", err)
	}

	return *resp, nil
}

package v1

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/GoYoko/web"

	"github.com/chaitin/MonkeyCode/backend/config"
	"github.com/chaitin/MonkeyCode/backend/consts"
	"github.com/chaitin/MonkeyCode/backend/domain"
	"github.com/chaitin/MonkeyCode/backend/errcode"
	"github.com/chaitin/MonkeyCode/backend/internal/middleware"
	"github.com/chaitin/MonkeyCode/backend/pkg/session"
	"github.com/chaitin/MonkeyCode/backend/pkg/vsix"
)

type UserHandler struct {
	usecase domain.UserUsecase
	euse    domain.ExtensionUsecase
	session *session.Session
	logger  *slog.Logger
	cfg     *config.Config
}

func NewUserHandler(
	w *web.Web,
	usecase domain.UserUsecase,
	euse domain.ExtensionUsecase,
	auth *middleware.AuthMiddleware,
	session *session.Session,
	logger *slog.Logger,
	cfg *config.Config,
) *UserHandler {
	u := &UserHandler{
		usecase: usecase,
		session: session,
		logger:  logger,
		cfg:     cfg,
		euse:    euse,
	}

	w.GET("/api/v1/static/vsix/:version", web.BaseHandler(u.VSIXDownload))
	w.GET("/api/v1/static/vsix", web.BaseHandler(u.VSIXDownload))
	w.POST("/api/v1/vscode/init-auth", web.BindHandler(u.VSCodeAuthInit))

	// admin
	admin := w.Group("/api/v1/admin")
	admin.POST("/login", web.BindHandler(u.AdminLogin))
	admin.GET("/setting", web.BaseHandler(u.GetSetting))

	admin.Use(auth.Auth())
	admin.PUT("/setting", web.BindHandler(u.UpdateSetting))
	admin.POST("/create", web.BindHandler(u.CreateAdmin))
	admin.GET("/list", web.BaseHandler(u.AdminList, web.WithPage()))
	admin.GET("/login-history", web.BaseHandler(u.AdminLoginHistory, web.WithPage()))
	admin.DELETE("/delete", web.BaseHandler(u.DeleteAdmin))

	// user
	g := w.Group("/api/v1/user")
	g.GET("/oauth/signup-or-in", web.BindHandler(u.OAuthSignUpOrIn))
	g.GET("/oauth/callback", web.BindHandler(u.OAuthCallback))
	g.POST("/register", web.BindHandler(u.Register))
	g.POST("/login", web.BindHandler(u.Login))

	g.Use(auth.Auth())

	g.PUT("/update", web.BindHandler(u.Update))
	g.DELETE("/delete", web.BaseHandler(u.Delete))
	g.GET("/invite", web.BaseHandler(u.Invite))
	g.GET("/list", web.BindHandler(u.List, web.WithPage()))
	g.GET("/login-history", web.BaseHandler(u.LoginHistory, web.WithPage()))

	return u
}

func (h *UserHandler) VSCodeAuthInit(c *web.Context, req domain.VSCodeAuthInitReq) error {
	resp, err := h.usecase.VSCodeAuthInit(c.Request().Context(), &req)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, resp)
}

// VSIXDownload 下载VSCode插件
//
//	@Tags			User
//	@Summary		下载VSCode插件
//	@Description	下载VSCode插件
//	@ID				vsix-download
//	@Accept			json
//	@Produce		octet-stream
//	@Router			/api/v1/static/vsix [get]
func (h *UserHandler) VSIXDownload(c *web.Context) error {
	v, err := h.euse.GetByVersion(c.Request().Context(), c.Param("version"))
	if err != nil {
		return err
	}
	disposition := fmt.Sprintf("attachment; filename=monkeycode-%s.vsix", v.Version)
	c.Response().Header().Set("Content-Type", "application/octet-stream")
	c.Response().Header().Set("Content-Disposition", disposition)
	if err := vsix.ChangeVsixEndpoint(v.Path, "extension/package.json", h.cfg.BaseUrl, c.Response().Writer); err != nil {
		return err
	}
	return nil
}

// Login 用户登录
//
//	@Tags			User
//	@Summary		用户登录
//	@Description	用户登录
//	@ID				login
//	@Accept			json
//	@Produce		json
//	@Param			param	body		domain.LoginReq	true	"登录参数"
//	@Success		200		{object}	web.Resp{data=domain.LoginResp}
//	@Router			/api/v1/user/login [post]
func (h *UserHandler) Login(c *web.Context, req domain.LoginReq) error {
	resp, err := h.usecase.Login(c.Request().Context(), &req)
	if err != nil {
		return err
	}
	return c.Success(resp)
}

// Update 更新用户
//
//	@Tags			User
//	@Summary		更新用户
//	@Description	更新用户
//	@ID				update-user
//	@Accept			json
//	@Produce		json
//	@Param			param	body		domain.UpdateUserReq	true	"更新用户参数"
//	@Success		200		{object}	web.Resp{data=domain.User}
//	@Router			/api/v1/user/update [put]
func (h *UserHandler) Update(c *web.Context, req domain.UpdateUserReq) error {
	resp, err := h.usecase.Update(c.Request().Context(), &req)
	if err != nil {
		return err
	}
	return c.Success(resp)
}

// Delete 删除用户
//
//	@Tags			User
//	@Summary		删除用户
//	@Description	删除用户
//	@ID				delete-user
//	@Accept			json
//	@Produce		json
//	@Param			id	query		string	true	"用户ID"
//	@Success		200	{object}	web.Resp{data=nil}
//	@Router			/api/v1/user/delete [delete]
func (h *UserHandler) Delete(c *web.Context) error {
	err := h.usecase.Delete(c.Request().Context(), c.QueryParam("id"))
	if err != nil {
		return err
	}
	return c.Success(nil)
}

// DeleteAdmin 删除管理员
//
//	@Tags			Admin
//	@Summary		删除管理员
//	@Description	删除管理员
//	@ID				delete-admin
//	@Accept			json
//	@Produce		json
//	@Param			id	query		string	true	"管理员ID"
//	@Success		200	{object}	web.Resp{data=nil}
//	@Router			/api/v1/admin/delete [delete]
func (h *UserHandler) DeleteAdmin(c *web.Context) error {
	err := h.usecase.DeleteAdmin(c.Request().Context(), c.QueryParam("id"))
	if err != nil {
		return err
	}
	return c.Success(nil)
}

// AdminLogin 管理员登录
//
//	@Tags			Admin
//	@Summary		管理员登录
//	@Description	管理员登录
//	@ID				admin-login
//	@Accept			json
//	@Produce		json
//	@Param			param	body		domain.LoginReq	true	"登录参数"
//	@Success		200		{object}	web.Resp{data=domain.AdminUser}
//	@Router			/api/v1/admin/login [post]
func (h *UserHandler) AdminLogin(c *web.Context, req domain.LoginReq) error {
	resp, err := h.usecase.AdminLogin(c.Request().Context(), &req)
	if err != nil {
		return err
	}

	h.logger.With("header", c.Request().Header).With("host", c.Request().Host).Info("admin login", "username", resp.Username)
	if _, err := h.session.Save(c, consts.SessionName, c.Request().Host, resp); err != nil {
		return err
	}
	return c.Success(resp)
}

// List 获取用户列表
//
//	@Tags			User
//	@Summary		获取用户列表
//	@Description	获取用户列表
//	@ID				list-user
//	@Accept			json
//	@Produce		json
//	@Param			page	query		web.Pagination	true	"分页"
//	@Success		200		{object}	web.Resp{data=domain.ListUserResp}
//	@Router			/api/v1/user/list [get]
func (h *UserHandler) List(c *web.Context, req domain.ListReq) error {
	resp, err := h.usecase.List(c.Request().Context(), req)
	if err != nil {
		return err
	}
	return c.Success(resp)
}

// LoginHistory 获取用户登录历史
//
//	@Tags			User
//	@Summary		获取用户登录历史
//	@Description	获取用户登录历史
//	@ID				login-history
//	@Accept			json
//	@Produce		json
//	@Param			page	query		web.Pagination	true	"分页"
//	@Success		200		{object}	web.Resp{data=domain.ListLoginHistoryResp}
//	@Router			/api/v1/user/login-history [get]
func (h *UserHandler) LoginHistory(c *web.Context) error {
	resp, err := h.usecase.LoginHistory(c.Request().Context(), c.Page())
	if err != nil {
		return err
	}
	return c.Success(resp)
}

// Invite 获取用户邀请码
//
//	@Tags			User
//	@Summary		获取用户邀请码
//	@Description	获取用户邀请码
//	@ID				invite
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	web.Resp{data=domain.InviteResp}
//	@Router			/api/v1/user/invite [get]
func (h *UserHandler) Invite(c *web.Context) error {
	user := middleware.GetUser(c)
	resp, err := h.usecase.Invite(c.Request().Context(), user.ID)
	if err != nil {
		return err
	}
	return c.Success(resp)
}

// Register 注册用户
//
//	@Tags			User
//	@Summary		注册用户
//	@Description	注册用户
//	@ID				register
//	@Accept			json
//	@Produce		json
//	@Param			param	body		domain.RegisterReq	true	"注册参数"
//	@Success		200		{object}	web.Resp{data=domain.User}
//	@Router			/api/v1/user/register [post]
func (h *UserHandler) Register(c *web.Context, req domain.RegisterReq) error {
	resp, err := h.usecase.Register(c.Request().Context(), &req)
	if err != nil {
		return err
	}

	return c.Success(resp)
}

// CreateAdmin 创建管理员
//
//	@Tags			Admin
//	@Summary		创建管理员
//	@Description	创建管理员
//	@ID				create-admin
//	@Accept			json
//	@Produce		json
//	@Param			param	body		domain.CreateAdminReq	true	"创建管理员参数"
//	@Success		200		{object}	web.Resp{data=domain.AdminUser}
//	@Router			/api/v1/admin/create [post]
func (h *UserHandler) CreateAdmin(c *web.Context, req domain.CreateAdminReq) error {
	user := middleware.GetUser(c)
	if user.Username != "admin" {
		return errcode.ErrPermission
	}
	resp, err := h.usecase.CreateAdmin(c.Request().Context(), &req)
	if err != nil {
		return err
	}
	return c.Success(resp)
}

// AdminList 获取管理员用户列表
//
//	@Tags			Admin
//	@Summary		获取管理员用户列表
//	@Description	获取管理员用户列表
//	@ID				list-admin-user
//	@Accept			json
//	@Produce		json
//	@Param			page	query		web.Pagination	true	"分页"
//	@Success		200		{object}	web.Resp{data=domain.ListAdminUserResp}
//	@Router			/api/v1/admin/list [get]
func (h *UserHandler) AdminList(c *web.Context) error {
	resp, err := h.usecase.AdminList(c.Request().Context(), c.Page())
	if err != nil {
		return err
	}
	return c.Success(resp)
}

// AdminLoginHistory 获取管理员登录历史
//
//	@Tags			Admin
//	@Summary		获取管理员登录历史
//	@Description	获取管理员登录历史
//	@ID				admin-login-history
//	@Accept			json
//	@Produce		json
//	@Param			page	query		web.Pagination	true	"分页"
//	@Success		200		{object}	web.Resp{data=domain.ListAdminLoginHistoryResp}
//	@Router			/api/v1/admin/login-history [get]
func (h *UserHandler) AdminLoginHistory(c *web.Context) error {
	resp, err := h.usecase.AdminLoginHistory(c.Request().Context(), c.Page())
	if err != nil {
		return err
	}
	return c.Success(resp)
}

// GetSetting 获取系统设置
//
//	@Tags			Admin
//	@Summary		获取系统设置
//	@Description	获取系统设置
//	@ID				get-setting
//	@Accept			json
//	@Produce		json
//	@Success		200	{object}	web.Resp{data=domain.Setting}
//	@Router			/api/v1/admin/setting [get]
func (h *UserHandler) GetSetting(c *web.Context) error {
	resp, err := h.usecase.GetSetting(c.Request().Context())
	if err != nil {
		return err
	}
	return c.Success(resp)
}

// UpdateSetting 更新系统设置
//
//	@Tags			Admin
//	@Summary		更新系统设置
//	@Description	更新系统设置
//	@ID				update-setting
//	@Accept			json
//	@Produce		json
//	@Param			param	body		domain.UpdateSettingReq	true	"更新系统设置参数"
//	@Success		200		{object}	web.Resp{data=domain.Setting}
//	@Router			/api/v1/admin/setting [put]
func (h *UserHandler) UpdateSetting(c *web.Context, req domain.UpdateSettingReq) error {
	resp, err := h.usecase.UpdateSetting(c.Request().Context(), &req)
	if err != nil {
		return err
	}
	return c.Success(resp)
}

// OAuthSignUpOrIn 用户 OAuth 登录或注册
//
//	@Tags			User
//	@Summary		用户 OAuth 登录或注册
//	@Description	用户 OAuth 登录或注册
//	@ID				user-oauth-signup-or-in
//	@Accept			json
//	@Produce		json
//	@Param			req	query		domain.OAuthSignUpOrInReq	true	"param"
//	@Success		200	{object}	web.Resp{data=domain.OAuthURLResp}
//	@Router			/api/v1/user/oauth/signup-or-in [get]
func (h *UserHandler) OAuthSignUpOrIn(ctx *web.Context, req domain.OAuthSignUpOrInReq) error {
	resp, err := h.usecase.OAuthSignUpOrIn(ctx.Request().Context(), &req)
	if err != nil {
		return err
	}
	return ctx.Success(resp)
}

// OAuthCallback 用户 OAuth 回调
//
//	@Tags			User
//	@Summary		用户 OAuth 回调
//	@Description	用户 OAuth 回调
//	@ID				user-oauth-callback
//	@Accept			json
//	@Produce		json
//	@Param			req	query		domain.OAuthCallbackReq	true	"param"
//	@Success		200	{object}	web.Resp{data=string}
//	@Router			/api/v1/user/oauth/callback [get]
func (h *UserHandler) OAuthCallback(ctx *web.Context, req domain.OAuthCallbackReq) error {
	resp, err := h.usecase.OAuthCallback(ctx.Request().Context(), &req)
	if err != nil {
		return err
	}
	ctx.Redirect(http.StatusFound, resp)
	return nil
}

func (h *UserHandler) InitAdmin() error {
	return h.usecase.InitAdmin(context.Background())
}

package v1

import (
	"github.com/GoYoko/web"

	"github.com/chaitin/MonkeyCode/backend/domain"
)

// List 获取用户扫描结果
//
//	@Tags			User Security Scanning
//	@Summary		获取用户扫描结果
//	@Description	获取用户扫描结果
//	@ID				user-security-scanning-list
//	@Accept			json
//	@Produce		json
//	@Param			page	query		domain.ListSecurityScanningReq	true	"参数"
//	@Success		200		{object}	web.Resp{data=domain.ListSecurityScanningResp}
//	@Failure		401		{object}	string
//	@Router			/api/v1/user/security/scanning [get]
func (u *UserHandler) SecurityList(c *web.Context, req domain.ListSecurityScanningReq) error {
	return nil
}

// Detail 获取用户扫描风险详情
//
//	@Tags			User Security Scanning
//	@Summary		获取用户扫描风险详情
//	@Description	获取用户扫描风险详情
//	@ID				user-security-scanning-detail
//	@Accept			json
//	@Produce		json
//	@Param			id	query		string	true	"扫描任务id"
//	@Success		200	{object}	web.Resp{data=[]domain.SecurityScanningRiskDetail}
//	@Failure		401	{object}	string
//	@Router			/api/v1/user/security/scanning/detail [get]
func (u *UserHandler) SecurityDetail(c *web.Context) error {
	return nil
}

package domain

import (
	"github.com/GoYoko/web"

	"github.com/chaitin/MonkeyCode/backend/consts"
)

type ListSecurityScanningReq struct {
	web.Pagination
	Author      string `json:"author" query:"author"`             // 作者
	ProjectName string `json:"project_name" query:"project_name"` // 项目名称
}

type ListSecurityScanningResp struct {
	web.PageInfo

	Items []*SecurityScanningResult `json:"items"`
}

type ListSecurityScanningBriefResp struct {
	web.PageInfo

	Items []*SecurityScanningBrief `json:"items"`
}

type SecurityScanningBrief struct {
	Workspace string                        `json:"workspace"`  // 项目目录
	Status    consts.SecurityScanningStatus `json:"status"`     // 扫描状态
	ReportURL string                        `json:"report_url"` // 报告url
	CreatedAt int64                         `json:"created_at"` // 创建时间
}

type CreateSecurityScanningReq struct {
	Workspace string                          `json:"workspace"` // 项目目录
	Language  consts.SecurityScanningLanguage `json:"language"`  // 扫描语言
}

type SecurityScanningResult struct {
	ID          string                        `json:"id"`           // 扫描任务id
	Name        string                        `json:"name"`         // 扫描任务
	ProjectName string                        `json:"project_name"` // 项目名称
	Status      consts.SecurityScanningStatus `json:"status"`       // 扫描状态
	Risk        SecurityScanningRiskResult    `json:"risk"`         // 风险结果
	User        *User                         `json:"user"`         // 用户
	CreatedAt   int64                         `json:"created_at"`   // 扫描开始时间
}

type SecurityScanningRiskResult struct {
	SevereCount   int `json:"severe_count"`   // 严重数
	CriticalCount int `json:"critical_count"` // 高危数
	SuggestCount  int `json:"suggest_count"`  // 建议数
}

type SecurityScanningRiskDetail struct {
	ID       string                           `json:"id"`       // 风险id
	Level    consts.SecurityScanningRiskLevel `json:"level"`    // 风险等级
	Desc     string                           `json:"desc"`     // 风险描述
	Filename string                           `json:"filename"` // 风险文件名
}

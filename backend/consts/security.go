package consts

type SecurityScanningStatus string

const (
	SecurityScanningStatusPending SecurityScanningStatus = "pending"
	SecurityScanningStatusRunning SecurityScanningStatus = "running"
	SecurityScanningStatusSuccess SecurityScanningStatus = "success"
	SecurityScanningStatusFailed  SecurityScanningStatus = "failed"
)

// 风险等级
type SecurityScanningRiskLevel string

const (
	SecurityScanningRiskLevelSevere   SecurityScanningRiskLevel = "severe"   // 严重
	SecurityScanningRiskLevelCritical SecurityScanningRiskLevel = "critical" // 高危
	SecurityScanningRiskLevelSuggest  SecurityScanningRiskLevel = "suggest"  // 建议
)

type SecurityScanningLanguage string

const (
	SecurityScanningLanguageCpp        SecurityScanningLanguage = "C/C++"
	SecurityScanningLanguageJava       SecurityScanningLanguage = "Java"
	SecurityScanningLanguagePython     SecurityScanningLanguage = "Python"
	SecurityScanningLanguageJavaScript SecurityScanningLanguage = "JavaScript"
	SecurityScanningLanguageGo         SecurityScanningLanguage = "Go"
	SecurityScanningLanguagePHP        SecurityScanningLanguage = "PHP"
	SecurityScanningLanguageCS         SecurityScanningLanguage = "C#"
	SecurityScanningLanguageSwift      SecurityScanningLanguage = "Swift"
	SecurityScanningLanguageRuby       SecurityScanningLanguage = "Ruby"
	SecurityScanningLanguageRust       SecurityScanningLanguage = "Rust"
	SecurityScanningLanguageHTML       SecurityScanningLanguage = "HTML"
	SecurityScanningLanguageObjectiveC SecurityScanningLanguage = "Objective-C/C++"
	SecurityScanningLanguageOCaml      SecurityScanningLanguage = "OCaml"
	SecurityScanningLanguageKotlin     SecurityScanningLanguage = "Kotlin"
	SecurityScanningLanguageScala      SecurityScanningLanguage = "Scala"
	SecurityScanningLanguageSolidity   SecurityScanningLanguage = "Solidity"
	SecurityScanningLanguageCOBOL      SecurityScanningLanguage = "COBOL"
	SecurityScanningLanguageShell      SecurityScanningLanguage = "Shell"
	SecurityScanningLanguageSQL        SecurityScanningLanguage = "SQL"
	SecurityScanningLanguageFortran    SecurityScanningLanguage = "Fortran"
	SecurityScanningLanguageDart       SecurityScanningLanguage = "Dart"
	SecurityScanningLanguageGroovy     SecurityScanningLanguage = "Groovy"
	SecurityScanningLanguageLua        SecurityScanningLanguage = "Lua"
	SecurityScanningLanguageSecrets    SecurityScanningLanguage = "Secrets"
	SecurityScanningLanguageIaC        SecurityScanningLanguage = "IaC"
)

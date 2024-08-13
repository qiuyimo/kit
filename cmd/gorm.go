package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type ApplicationDomain struct {
	ID        int64  `gorm:"column:id;primaryKey;autoIncrement" json:"id"`
	AppID     int64  `gorm:"column:app_id;type:int(11);not null;comment:应用ID;index:idx_app_id" json:"app_id"`
	Name      string `gorm:"column:name;type:varchar(100);not null;comment:域名;uniqueIndex:udx_name" json:"name"`
	CertID    int64  `gorm:"column:cert_id;type:int(11);not null;comment:证书id" json:"cert_id"`
	Redirect  *bool  `gorm:"column:redirect;not null;comment:是否重定向" json:"redirect"`
	Location  string `gorm:"column:location;type:varchar(100);not null;comment:重定向域名" json:"location"`
	CreatedAt int64  `gorm:"column:created_at;type:bigint(20);not null;comment:创建时间" json:"-"`
	UpdatedAt int64  `gorm:"column:updated_at;type:bigint(20);not null;comment:更新时间" json:"-"`
}

// gormCmd represents the gorm command
var gormCmd = &cobra.Command{
	Use:   "gorm",
	Short: "测试 gorm 语句",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("gorm called")

		dsn := "root:root@tcp(192.168.3.230:3306)/vip?charset=utf8mb4&parseTime=True&loc=Local"
		db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err != nil {
			panic(err)
		}

		type AppAndDomainInfo struct {
			RequestScheme string `json:"request_scheme"`
			DomainName    string `json:"domain_name"`
		}

		var result []AppAndDomainInfo
		err = db.Model(&ApplicationDomain{}).Select("application_domains.name as domain_name, applications.request_scheme as request_scheme").
			Joins("left join applications on application_domains.app_id = applications.id").
			Where("applications.type = ?", 2).Scan(&result).Error
		if err != nil {
			panic(err)
		}
		fmt.Println(result)
	},
}

func init() {
	rootCmd.AddCommand(gormCmd)
}

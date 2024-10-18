package driver

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/wwqdrh/gokit/logger"
)

var (
	ErrNotAuth = errors.New("no auth")
	ErrInvUrl  = errors.New("invalid url")
)

type FileItem struct {
	Name          string
	Href          string
	Owner         string
	Status        string
	ResourceType  interface{}
	ContentType   string
	ContentLength int64
	LastModify    string
	Privileges    []string
}

type IDriver interface {
	// 认证
	Auth(name, password string)
	IsAuth() bool
	// 文件信息
	SetIgnore(p []string)
	GetLastTimeline(name string) string
	GetLastTimelineMap() map[string]int64
	GetStat(url string) ([]byte, string, error)
	// 数据操作
	GetData(url string) ([]byte, error)
	UpdateData(data io.Reader, url string) error
	// 文件操作
	List(url string) ([]FileItem, error)
	Delete(url string) error
	Update(local, url string) error
}

type DriverConfigAll struct {
	cfg     string
	data    map[string]*DriverConfig
	drivers map[string]IDriver
}

type DriverConfig struct {
	Username  string            `json:"username"`
	Password  string            `json:"password"`
	Ignores   []string          `json:"ignores"`
	TimeLines map[string]string `json:"timelines"` // 存储各个文件的上次上传时间
}

type IDriverConfig interface {
	GetLastTimeline(mode string, pname string) string // 获取文件的上次上传时间
	SetLastTimeline(mode string, pname string)        // 设置文件上次上传时间
	GetLastTimelineMap(mode string) map[string]int64
	GetConfig(mode string) (*DriverConfig, bool)
	GetDriver(name string) (IDriver, error)
	Close()
}

// var defaultDriverData = map[string]DriverConfig{
// 	"坚果云": {
// 		Username: "",
// 		Password: "",
// 	},
// }

func NewDriverConfig(config map[string]*DriverConfig) IDriverConfig {
	return &DriverConfigAll{
		cfg:     "",
		data:    config,
		drivers: map[string]IDriver{},
	}
}

func NewDriverConfigAll(cfg string) (IDriverConfig, error) {
	data, err := os.ReadFile(cfg)
	if err != nil {
		return nil, err
	}

	var config map[string]*DriverConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &DriverConfigAll{
		cfg:  cfg,
		data: config,
	}, nil
}

// 读取homePath下config.json中name部分的数据
func (c *DriverConfigAll) GetDriver(name string) (IDriver, error) {
	if v, ok := c.drivers[name]; ok {
		return v, nil
	}

	driverConfig, ok := c.GetConfig(name)
	if !ok {
		return nil, errors.New("no auth, pls update config.json") // 如果name不存在，返回空DriverConfig
	}

	switch name {
	case "坚果云":
		d := NewJianguoDriver(c)
		d.Auth(driverConfig.Username, driverConfig.Password)
		d.SetIgnore(driverConfig.Ignores)
		c.drivers[name] = d
		return d, nil
	default:
		return nil, errors.New("no this driver")
	}
}

func (c *DriverConfigAll) Close() {

}

func (c *DriverConfigAll) GetLastTimeline(mode string, pname string) string {
	cfg, ok := c.data[mode]
	if !ok {
		return ""
	}
	lastupdate, ok := cfg.TimeLines[pname]
	if !ok {
		return ""
	}
	return lastupdate
}

func (c *DriverConfigAll) GetLastTimelineMap(mode string) map[string]int64 {
	cfg, ok := c.data[mode]
	if !ok {
		return map[string]int64{}
	}

	res := map[string]int64{}
	for name, t := range cfg.TimeLines {
		tt, err := time.Parse(time.RFC3339, t)
		if err != nil {
			logger.DefaultLogger.Warn(err.Error())
			continue
		}
		res[name] = tt.UnixNano()
	}
	return res
}

func (c *DriverConfigAll) SetLastTimeline(mode string, pname string) {
	cfg, ok := c.data[mode]
	if !ok {
		return
	}
	if cfg.TimeLines == nil {
		cfg.TimeLines = map[string]string{}
	}
	cfg.TimeLines[pname] = time.Now().Format(time.RFC3339)
	c.dump()
}

func (c *DriverConfigAll) GetConfig(mode string) (*DriverConfig, bool) {
	config, ok := c.data[mode]
	return config, ok
}

func (c *DriverConfigAll) dump() {
	if c.cfg == "" {
		return
	}

	data, err := json.Marshal(c.data)
	if err != nil {
		logger.DefaultLogger.Warn(err.Error())
		return
	}
	err = os.WriteFile(c.cfg, data, 0644)
	if err != nil {
		logger.DefaultLogger.Warn(err.Error())
		return
	}
}

package webdav

import (
	"encoding/json"

	"github.com/pkg/errors"
	"github.com/wwqdrh/webdav/driver"
)

var (
	ErrInvalidParam = errors.New("invalid param")
)

var runtimeDriver driver.IDriverConfig

func NewRuntimeDriver(cfg map[string]interface{}) error {
	cfgData, err := json.Marshal(cfg)
	if err != nil {
		return errors.Wrapf(ErrInvalidParam, err.Error())
	}

	var spec map[string]*driver.DriverConfig
	if err := json.Unmarshal(cfgData, &spec); err != nil {
		return errors.Wrapf(ErrInvalidParam, err.Error())
	}

	runtimeDriver = driver.NewDriverConfig(spec)
	return nil
}

func RuntimeClose() {
	if runtimeDriver != nil {
		runtimeDriver.Close()
	}
}

// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package adapter

import (
	"bytes"
	"encoding/json"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"

	"github.com/wwqdrh/gokit/logger"
	"github.com/wwqdrh/webdav/driver"
)

type CasbinRule struct {
	PType string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

// Adapter represents the Redis adapter for policy storage.
// It can load policy from JSON bytes or save policy to JSON bytes.
type Adapter struct {
	source []byte // default value
	policy []CasbinRule
	// webdav
	dataurl string
	driver  driver.IDriver
}

// NewAdapter is the constructor for Adapter.
// source是当url不存在时的默认值
func NewAdapter(driver driver.IDriver, url string, source []byte, force bool) persist.Adapter {
	a := Adapter{
		dataurl: url,
		driver:  driver,
		policy:  []CasbinRule{},
	}

	a.source = source
	if force {
		a.loadFromBuffer()
		a.saveToBuffer()
	} else {
		if a.driver != nil {
			content, err := a.driver.GetData(url)
			if err != nil {
				logger.DefaultLogger.Warn(err.Error())
			} else {
				a.source = content
			}
		}
	}
	return &a
}

func (a *Adapter) saveToBuffer() error {
	data, err := json.Marshal(a.policy)
	if err != nil {
		return err
	}

	a.source = data
	if a.driver != nil {
		return a.driver.UpdateData(bytes.NewReader(data), a.dataurl)
	} else {
		return err
	}
}

func (a *Adapter) loadFromBuffer() error {
	if len(a.source) == 0 {
		return nil
	}

	var policy []CasbinRule
	err := json.Unmarshal(a.source, &policy)
	if err == nil {
		a.policy = policy
	}
	return err
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	lineText := line.PType
	if line.V0 != "" {
		lineText += ", " + line.V0
	}
	if line.V1 != "" {
		lineText += ", " + line.V1
	}
	if line.V2 != "" {
		lineText += ", " + line.V2
	}
	if line.V3 != "" {
		lineText += ", " + line.V3
	}
	if line.V4 != "" {
		lineText += ", " + line.V4
	}
	if line.V5 != "" {
		lineText += ", " + line.V5
	}

	persist.LoadPolicyLine(lineText, model)
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	err := a.loadFromBuffer()
	if err != nil {
		return err
	}

	for _, line := range a.policy {
		loadPolicyLine(line, model)
	}
	return nil
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{}

	line.PType = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	a.policy = []CasbinRule{}

	var lines []CasbinRule

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	a.policy = lines

	err := a.saveToBuffer()
	return err
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	a.policy = append(a.policy, line)
	return a.saveToBuffer()
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	diff := max(0, 6-len(rule))
	for i := 0; i < diff; i++ {
		rule = append(rule, "")
	}
	for i, line := range a.policy {
		if line.PType == ptype &&
			line.V0 == rule[0] &&
			line.V1 == rule[1] &&
			line.V2 == rule[2] &&
			line.V3 == rule[3] &&
			line.V4 == rule[4] &&
			line.V5 == rule[5] {
			a.policy = append(a.policy[:i], a.policy[i+1:]...)
			return a.saveToBuffer()
		}
	}
	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	var newPolicy []CasbinRule
	for _, line := range a.policy {
		if line.PType != ptype {
			newPolicy = append(newPolicy, line)
			continue
		}

		matched := true
		for i, fieldValue := range fieldValues {
			if fieldValue == "" {
				continue
			}

			switch fieldIndex + i {
			case 0:
				if line.V0 != fieldValue {
					matched = false
				}
			case 1:
				if line.V1 != fieldValue {
					matched = false
				}
			case 2:
				if line.V2 != fieldValue {
					matched = false
				}
			case 3:
				if line.V3 != fieldValue {
					matched = false
				}
			case 4:
				if line.V4 != fieldValue {
					matched = false
				}
			case 5:
				if line.V5 != fieldValue {
					matched = false
				}
			}

			if !matched {
				break
			}
		}

		if !matched {
			newPolicy = append(newPolicy, line)
		}
	}

	a.policy = newPolicy
	return a.saveToBuffer()
}

package adapter

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/joho/godotenv"
	"github.com/wwqdrh/webdav/driver"
)

const testWebdavData = "test/webdav/policy.json"

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	myRes, _ := e.GetPolicy()
	log.Print("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func errorExpected(t *testing.T, err error) {
	if err == nil {
		t.Error("expected error")
	}
}
func testGetJianguoDriver(t *testing.T) (driver.IDriver, bool) {
	godotenv.Load("testdata/env")

	d := driver.NewJianguoDriver(nil)
	d.Auth(os.Getenv("jianguousername"), os.Getenv("jianguopassword"))
	if !d.IsAuth() {
		t.Skip("no webdav env, skip")
		return d, false
	}
	return d, true
}

func TestAdapter(t *testing.T) {
	d, ok := testGetJianguoDriver(t)
	if !ok {
		return
	}

	b, _ := os.ReadFile(filepath.Join("testdata", "rbac_policy.json"))
	a := NewAdapter(d, testWebdavData, b, true)
	e, _ := casbin.NewEnforcer("testdata/rbac_model.conf", a)
	e.GetPolicy()

	// Now the JSON Buffer has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a = NewAdapter(d, testWebdavData, b, true)
	e, _ = casbin.NewEnforcer("testdata/rbac_model.conf", a)
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	//Test Clear Policy
	e.ClearPolicy()
	testGetPolicy(t, e, [][]string{})

	// Test Add Policy
	_, _ = e.AddPolicy("alice", "data1", "read")
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}})

	// Add policies with up to 6 rule elements
	_, _ = e.AddPolicy("alice", "data1", "read", "indeterminate")
	_, _ = e.AddPolicy("alice", "domain1", "data1", "write", "indeterminate")
	_, _ = e.AddPolicy("alice", "domain1", "data1", "write", "indeterminate", "foo")
	_, _ = e.AddPolicy("alice", "domain1", "data1", "write", "indeterminate", "foo", "bar")

	// Add grouping policy
	_, _ = e.AddGroupingPolicy("alice", "data2_admin")

	// Test Save Policy
	policys, _ := e.GetPolicy()
	groups, _ := e.GetGroupingPolicy()
	expectedPolicies := len(policys) + len(groups)
	_ = e.SavePolicy()
	if len(a.policy) != expectedPolicies {
		t.Errorf("expected %d policies, got %d", expectedPolicies, len(a.policy))
	}

	// Not implemented methods
	// 添加策略
	ok, _ = e.AddPolicy("alice", "data1", "read")
	if !ok {
		t.Error("add policy failed")
	}

	// 删除策略
	ok, _ = e.RemovePolicy("alice", "data1", "read")
	if !ok {
		t.Error("remove policy failed")
	}

	// 删除过滤后的策略
	ok, _ = e.RemoveFilteredPolicy(0, "alice")
	if !ok {
		t.Error("add policy failed")
	}
}

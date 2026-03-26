package rules

import (
	"sync"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	ruleTypes "github.com/aquasecurity/trivy/pkg/iac/types/rules"
	"github.com/aquasecurity/trivy/pkg/set"
)

type registry struct {
	sync.RWMutex
	index      int
	frameworks map[framework.Framework][]ruleTypes.RegisteredRule
}

var coreRegistry = registry{
	frameworks: make(map[framework.Framework][]ruleTypes.RegisteredRule),
}

func Reset() {
	coreRegistry.Reset()
}

func Register(rule scan.Rule) ruleTypes.RegisteredRule {
	return coreRegistry.register(rule)
}

func Deregister(rule ruleTypes.RegisteredRule) {
	coreRegistry.deregister(rule)
}

func (r *registry) register(rule scan.Rule) ruleTypes.RegisteredRule {
	r.Lock()
	defer r.Unlock()
	if len(rule.Frameworks) == 0 {
		rule.Frameworks = map[framework.Framework][]string{framework.Default: nil}
	}
	registeredRule := ruleTypes.RegisteredRule{
		Number: r.index,
		Rule:   rule,
	}
	r.index++
	for fw := range rule.Frameworks {
		r.frameworks[fw] = append(r.frameworks[fw], registeredRule)
	}

	r.frameworks[framework.ALL] = append(r.frameworks[framework.ALL], registeredRule)

	return registeredRule
}

func (r *registry) deregister(rule ruleTypes.RegisteredRule) {
	r.Lock()
	defer r.Unlock()
	for fw := range r.frameworks {
		for i, registered := range r.frameworks[fw] {
			if registered.Number == rule.Number {
				r.frameworks[fw] = append(r.frameworks[fw][:i], r.frameworks[fw][i+1:]...)
				break
			}
		}
	}
}

func (r *registry) getFrameworkRules(fw ...framework.Framework) []ruleTypes.RegisteredRule {
	r.RLock()
	defer r.RUnlock()
	var registered []ruleTypes.RegisteredRule
	if len(fw) == 0 {
		fw = []framework.Framework{framework.Default}
	}
	unique := set.New[int]()
	for _, f := range fw {
		for _, rule := range r.frameworks[f] {
			if unique.Contains(rule.Number) {
				continue
			}
			registered = append(registered, rule)
			unique.Append(rule.Number)
		}
	}
	return registered
}

func (r *registry) Reset() {
	r.Lock()
	defer r.Unlock()
	r.frameworks = make(map[framework.Framework][]ruleTypes.RegisteredRule)
}

func GetFrameworkRules(fw ...framework.Framework) []ruleTypes.RegisteredRule {
	return coreRegistry.getFrameworkRules(fw...)
}

func GetRegistered(fw ...framework.Framework) []ruleTypes.RegisteredRule {
	return GetFrameworkRules(fw...)
}

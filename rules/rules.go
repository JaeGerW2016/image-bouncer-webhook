package rules

import (
	"fmt"
	"github.com/containers/image/docker/reference"
	"strings"
)

func IsWhitelistNamespace(nsarr []string, ns string) bool {
	for _, n := range nsarr {
		if n == ns || strings.Contains(ns, n) {
			return true
		}
	}
	return false
}

func IsUsingLatestTag(image string) (bool, error) {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return false, err
	}
	str := reference.TagNameOnly(named).String()
	return strings.HasSuffix(str, ":latest"), nil
}

func IsFromWhiteListedRegistry(image string, whitelist []string) (bool, error) {
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return false, err
	}
	res := strings.SplitN(named.Name(), "/", 2)
	if len(res) != 2 {
		return false,fmt.Errorf("error while identifying the registry of %s", image)
	}

	for _, allowed := range whitelist {
		if res[0] == allowed {
			return true, nil
		}
	}

	return false, nil
}

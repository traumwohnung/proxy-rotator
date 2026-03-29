package bottingtools

import (
	"fmt"
	"strings"

	"proxy-gateway/core"
)

func BuildUsername(accountUser string, product ProductConfig, meta core.Meta) string {
	switch product.Type {
	case "residential":
		return buildResidential(accountUser, product.Residential, meta)
	case "isp":
		return buildISP(accountUser, product.ISP, meta)
	case "datacenter":
		return buildDatacenter(accountUser, product.Datacenter)
	default:
		return accountUser
	}
}

func buildResidential(accountUser string, cfg *ResidentialConfig, meta core.Meta) string {
	parts := []string{fmt.Sprintf("%s_pool-custom_type-%s", accountUser, cfg.Quality.AsTypeStr())}
	if country := pickCountry(cfg.Countries); country != "" {
		parts = append(parts, fmt.Sprintf("country-%s", strings.ToUpper(country.AsParamStr())))
	}
	if cfg.City != "" {
		parts = append(parts, fmt.Sprintf("city-%s", cfg.City))
	}
	parts = append(parts, fmt.Sprintf("session-%s", randomSessionID()))
	if v := sesstimeStr(meta); v != "" {
		parts = append(parts, fmt.Sprintf("sesstime-%s", v))
	}
	if meta.GetString("fastmode") == "true" {
		parts = append(parts, "fastmode-true")
	}
	return strings.Join(parts, "_")
}

func buildISP(accountUser string, cfg *ISPConfig, meta core.Meta) string {
	parts := []string{fmt.Sprintf("%s_pool-isp", accountUser)}
	if country := pickCountry(cfg.Countries); country != "" {
		parts = append(parts, fmt.Sprintf("country-%s", country.AsParamStr()))
	}
	parts = append(parts, fmt.Sprintf("session-%s", randomSessionID()))
	if v := sesstimeStr(meta); v != "" {
		parts = append(parts, fmt.Sprintf("sesstime-%s", v))
	}
	return strings.Join(parts, "_")
}

func buildDatacenter(accountUser string, cfg *DatacenterConfig) string {
	parts := []string{fmt.Sprintf("%s_pool-dc", accountUser)}
	if country := pickCountry(cfg.Countries); country != "" {
		parts = append(parts, fmt.Sprintf("country-%s", country.AsParamStr()))
	}
	return strings.Join(parts, "_")
}

func RotateSessionID(username string) string {
	newID := randomSessionID()
	parts := strings.Split(username, "_")
	replaced := false
	for i, part := range parts {
		if !replaced && strings.HasPrefix(part, "session-") {
			parts[i] = "session-" + newID
			replaced = true
		}
	}
	return strings.Join(parts, "_")
}

func pickCountry(countries []core.Country) core.Country {
	if len(countries) == 0 {
		return ""
	}
	return countries[int(core.CheapRandom())%len(countries)]
}

func sesstimeStr(meta core.Meta) string {
	v := meta["sesstime"]
	if v == nil {
		return ""
	}
	switch vv := v.(type) {
	case string:
		return vv
	case float64:
		return fmt.Sprintf("%g", vv)
	default:
		return fmt.Sprintf("%v", vv)
	}
}

func randomSessionID() string {
	a := core.CheapRandom()
	b := core.CheapRandom()
	return fmt.Sprintf("%016x", a^(b<<32))
}

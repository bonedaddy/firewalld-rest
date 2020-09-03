package firewallcmd

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

//EnableRichRuleForIP enables rich rule for IP access + reloads
//example:
//firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="10.10.99.10/32" port protocol="tcp" port="22" accept'
func EnableRichRuleForIP(ipAddr string) (string, error) {
	cmd1 := exec.Command(`firewall-cmd`, `--permanent`, "--zone=public", `--add-rich-rule=rule family="ipv4" source address="`+ipAddr+`/32" port protocol="tcp" port="22" accept`)
	//uncomment for debugging
	// for _, v := range cmd1.Args {
	// 	fmt.Println(v)
	// }
	output1, err1 := cmd1.CombinedOutput()
	if err1 != nil {
		return cmd1.String(), err1
	}
	fmt.Printf("rich rule added successfully for ip %v : %v", ipAddr, string(output1))

	cmd2, output2, err2 := reload()
	if err2 != nil {
		return cmd2.String(), err2
	}
	fmt.Printf("firewalld reloaded successfully : %v", string(output2))
	return "", nil
}

//DisableRichRuleForIP disables rich rule for IP access + reloads
func DisableRichRuleForIP(ipAddr string) (string, error) {
	cmd1 := exec.Command(`firewall-cmd`, `--permanent`, "--zone=public", `--remove-rich-rule=rule family="ipv4" source address="`+ipAddr+`/32" port protocol="tcp" port="22" accept`)
	output1, err1 := cmd1.CombinedOutput()
	if err1 != nil {
		return cmd1.String(), err1
	}
	fmt.Printf("rich rule deleted successfully for ip %v : %v", ipAddr, string(output1))

	cmd2, output2, err2 := reload()
	if err2 != nil {
		return cmd2.String(), err2
	}
	fmt.Printf("firewalld reloaded successfully : %v", string(output2))
	return "", nil
}

//reload reloads firewall for setting to take effect
func reload() (*exec.Cmd, []byte, error) {
	cmd := exec.Command("firewall-cmd", "--reload")
	output, err := cmd.CombinedOutput()
	return cmd, output, err
}

//GetIPSInFirewall gets IPs currently in firewall
func GetIPSInFirewall() ([]string, error) {

	var ipsInFirewall []string
	cmd := exec.Command("firewall-cmd", "--zone=public", "--list-rich-rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error while fetching IPs from firewall-cmd, err: %v", err)
	}
	richRules := string(output)
	//rule family="ipv4" source address="73.223.28.39/32" port port="22" protocol="tcp" accept
	//rule family="ipv4" source address="73.223.28.40/32" port port="22" protocol="tcp" accept

	ruleLines := strings.Split(richRules, "\n")

	stringToSearch := "address=\""
	for _, rule := range ruleLines {
		//fmt.Println(line)
		//r, _ := regexp.Compile("source address=\"[0-9]*(.)")
		r, _ := regexp.Compile(stringToSearch + "[0-9.]*")
		ipAddr := strings.TrimPrefix(r.FindString(rule), stringToSearch)
		if ipAddr != "" {
			ipsInFirewall = append(ipsInFirewall, ipAddr)
			fmt.Println(ipAddr)
		}
	}

	return ipsInFirewall, err
}

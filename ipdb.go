package ipdb

import (
    "fmt"
    "github.com/glebtv/whois"
    "strings"
    "strconv"
    "net"
    "time"
    "encoding/json"
    "io/ioutil"
    "os"
   // "flag"
    "log"
)


type IpData struct {
 Asn int64
 Prefix string
 Registry string
 AsnName string
 Country string
 Timestamp int64
 Aliases []IpData
}

const (
	// Team Cymru whois server.
	TeamCymru = "whois.cymru.com"
	LanAsn = 65500
	LanAsnName = "LAN"
	LanPrefix = "192.168.1.0/24"
	PrefixDbFile = "/tmp/prefixdb.json"
	Week = 604800
	PrivateAsn = 4200000000
	PrivateAsnName = "PRIVATE"
)

func (s IpData) print() {
 fmt.Printf("%+v", s)
}

/*
func countRune(s string, r rune) int {
    count := 0
    for _, c := range s {
        if c == r {
            count++
        }
    }
    return count
}
*/

func formatData(ss []string) IpData {
	var ip_data IpData
	t := time.Now()
	for i, d := range ss {
        	d = strings.TrimSpace(d)
                if i == 0 { d, _ := strconv.ParseInt(d, 10, 64); ip_data.Asn = d}
                if i == 2 { ip_data.Prefix = d}
                if i == 3 { ip_data.Registry = d}
                if i == 4 {
                	cc_name := strings.SplitN(d, ",", 2)
                        for j, dd := range cc_name {
                        	dd = strings.TrimSpace(dd)
                                if j == 0 { ip_data.AsnName = dd }
                                if j == 1 { ip_data.Country = dd}
                        }
                }
       	}
        ip_data.Timestamp = t.Unix()
	return  ip_data
}

func getIpWhoisData(ip string) IpData{
	var ip_data IpData
	var ss []string
	//t := time.Now()

	var ip_string = "-n -f -p -w -u -r  " + strings.Replace(ip, " ", "", -1)
	whois_raw, err := whois.Query(ip_string, TeamCymru)
	if err == nil {
		//num := countRune(whois_raw, '\n')
		//fmt.Println(num)
		for i, line := range strings.Split(strings.TrimSuffix(whois_raw, "\n"), "\n") {
			whois_raw = strings.Replace(line, "\n", "", -1)
                        whois_raw = strings.Trim(whois_raw, "\t \n")
                        ss = strings.SplitN(whois_raw, "|", 5)
			if i == 0 {
				ip_data = formatData(ss)
			} else {
				fmt.Println(i)
				ip_data.Aliases = append(ip_data.Aliases, formatData(ss))
			}
		}
	}
	return ip_data
}


func readFile(storage_path string) map[string]IpData {
	var ipsMap = make(map[string]IpData)
	jsonFile, err := os.Open(storage_path)
	// if we os.Open returns an error then handle it
	if err != nil {
    		log.Fatal(err)
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(byteValue, &ipsMap)

	return ipsMap
}


func getIpData(ipaddress string, lannetwork string, ipsMap map[string]IpData, lan_asn int64, lan_asn_name string, private_asn int64, private_asn_name string, refresh int64, ) map[string]IpData {
	var ip_data IpData
	t := time.Now()

        ip_address := net.ParseIP(strings.Replace(ipaddress, " ", "", -1))
	_, lan_network, err := net.ParseCIDR(strings.Replace(lannetwork, " ", "", -1))

        if err != nil {
                log.Fatal(err)
        }

	// IP in our file
        data, exists := ipsMap[strings.Replace(ipaddress, " ", "", -1)]

	// IP in our file
        if exists {
		if !lan_network.Contains(ip_address) && !ip_address.IsPrivate()  {
                	duration := refresh + data.Timestamp
			if duration < t.Unix() {
                        	ip_data = getIpWhoisData(ipaddress)
                        	ipsMap[strings.Replace(ipaddress, " ", "", -1)] = ip_data
                        	return ipsMap
			}
                }
        } else {
        	// IP from the lan, create dummy IpData
        	if lan_network.Contains(ip_address){
                	ip_data.Asn = lan_asn
                	ip_data.Prefix = strings.Replace(lannetwork, " ", "", -1)
                	ip_data.Registry = lan_asn_name
                	ip_data.AsnName = lan_asn_name
                	ip_data.Country = lan_asn_name
			ip_data.Timestamp = t.Unix()
                	ipsMap[strings.Replace(ipaddress, " ", "", -1)] = ip_data
			return ipsMap

        	}

		// Private IP

		if ip_address.IsPrivate(){
			ip_data.Asn = private_asn
                	ip_data.Prefix = strings.Replace(lannetwork, " ", "", -1)
                	ip_data.Registry = private_asn_name
                	ip_data.AsnName = private_asn_name
                	ip_data.Country = private_asn_name
                	ip_data.Timestamp = t.Unix()
                	ipsMap[strings.Replace(ipaddress, " ", "", -1)] = ip_data
                	return ipsMap
		}

		// Get new IP whois data
        	ip_data = getIpWhoisData(ipaddress)
        	ipsMap[strings.Replace(ipaddress, " ", "", -1)] = ip_data
	}


	return  ipsMap
}


func GetIpInfo(ip string, lan string, lan_asn int64, lan_asn_name string, private_asn int64, private_asn_name string, storage_path string, refresh int64) IpData {
	 _, err := os.Stat(storage_path)
         if err != nil {
                backupFile, err := os.Create(storage_path)
                if err != nil {
                        log.Fatal(err)
                }
                defer backupFile.Close()
        }

        var ipsMap = readFile(storage_path)


        ip_address := strings.Replace(ip, " ", "", -1)
        lan_network := strings.Replace(lan, " ", "", -1)

        ipsMap = getIpData(ip_address, lan_network, ipsMap, lan_asn, lan_asn_name, private_asn, private_asn_name, refresh)

	file, _ := json.MarshalIndent(ipsMap, "", " ")

        _ = ioutil.WriteFile(storage_path, file, 0644)

	return ipsMap[strings.Replace(ip, " ", "", -1)]
}

/*
var(
	lan_net = flag.String("lan.prefix", LanPrefix, "Prefix that should be considered as LAN.")
	lan_asn = flag.Int64("lan.asn", LanAsn, "ASN that should be considered as LAN.")
	lan_asn_name = flag.String("lan.asn-name", LanAsnName, "ASN Name that should be considered as LAN.")
	private_asn = flag.Int64("private.asn", PrivateAsn, "ASN that should be considered for private IPs (except your LAN).")
	private_asn_name = flag.String("private.asn-name", PrivateAsnName, "ASN Name that should be considered for private IPs (except your LAN).")
	storage_file = flag.String("storage.file", PrefixDbFile, "File to store or retrive IP data.")
	refresh_info = flag.Int64("data-expiry", Week, "How long IP information in your local file is valid for.")
)



func main() {

	flag.Parse()
	ip := " 198.168.1.1  "
	ip_data := GetIpInfo(ip, *lan_net, *lan_asn, *lan_asn_name, *private_asn, *private_asn_name, *storage_file, *refresh_info)
	fmt.Println()
	ip_data.print()

}
*/

package ovh

import (
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"log"
	"net"
	"strings"
	"time"

	"github.com/ovh/go-ovh/ovh"
)

type OvhIpFirewallRuleCreateOpts struct {
	Action          string `json:"action"`
	DestinationPort string `json:"destinationPort,omitempty"`
	Fragments       bool   `json:"fragments,omitempty"`
	Protocol        string `json:"protocol"`
	Sequence        int    `json:"sequence"`
	Source          string `json:"source,omitempty"`
	SourcePort      string `json:"sourcePort,omitempty"`
	TcpOption       string `json:"tcpOption,omitempty"`
}

type OvhIpFirewallRuleResponse struct {
	Action          string `json:"action"`
	CreationDate    string `json:"creationDate"`
	Destination     string `json:"destination"`
	DestinationPort string `json:"destinationPort"`
	Fragments       bool   `json:"fragments"`
	Protocol        string `json:"protocol"`
	Rule            string `json:"rule"`
	Sequence        int    `json:"sequence"`
	Source          string `json:"source"`
	SourcePort      string `json:"sourcePort"`
	State           string `json:"state"`
	TcpOption       string `json:"tcpOption"`
}

func resourceOvhIpFirewallRule() *schema.Resource {
	return &schema.Resource{
		Create: resourceOvhIpFirewallRuleCreate,
		Read:   resourceOvhIpFirewallRuleRead,
		Delete: resourceOvhIpFirewallRuleDelete,
		Importer: &schema.ResourceImporter{
			State: resourceOvhIpFirewallRuleImportState,
		},
		CustomizeDiff: resourceOvhIpFirewallRuleCustomizeDiff,

		Schema: map[string]*schema.Schema{
			"ip": {
				Type:        schema.TypeString,
				Description: "IP block",
				Required:    true,
				ForceNew:    true,
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					err := validateIpBlock(v.(string))
					if err != nil {
						errors = append(errors, err)
					}
					return
				},
			},
			"ip_on_firewall": {
				Type:        schema.TypeString,
				Description: "IP address",
				Optional:    true,
				ForceNew:    true,
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					err := validateIp(v.(string))
					if err != nil {
						errors = append(errors, err)
					}
					return
				},
			},
			"sequence": {
				Type:     schema.TypeInt,
				Required: true,
				ForceNew: true,
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					value := v.(int)
					if value < 0 || value > 19 {
						errors = append(errors, fmt.Errorf("Sequence not in 0..19 range"))
					}
					return
				},
			},
			"action": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Action on this rule",
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					err := validateStringEnum(v.(string), []string{"deny", "permit"})
					if err != nil {
						errors = append(errors, err)
					}
					return
				},
			},
			"protocol": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Network protocol",
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					err := validateStringEnum(v.(string), []string{"ah", "esp", "gre", "icmp", "ipv4", "tcp", "udp"})
					if err != nil {
						errors = append(errors, err)
					}
					return
				},
			},
			"source": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				ForceNew:    true,
				Description: "Source ip for your rule",
			},
			"source_port": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Source port range for your rule. Only with TCP/UDP protocol",
			},
			"destination_port": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "Destination port range for your rule. Only with TCP/UDP protocol",
			},
			"fragments": {
				Type:        schema.TypeBool,
				Description: "Fragments option",
				Optional:    true,
				ForceNew:    true,
				Default:     false,
			},
			"tcp_option": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "TCP option on your rule",
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					if len(v.(string)) > 0 {
						err := validateStringEnum(v.(string), []string{"syn", "established"})
						if err != nil {
							errors = append(errors, err)
						}
					}
					return
				},
			},
			"creation_date": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"rule": {
				Type:        schema.TypeString,
				Description: "Summary of rule",
				Computed:    true,
			},
			"state": {
				Type:        schema.TypeString,
				Description: "Current state of your rule",
				Computed:    true,
			},
		},
	}
}

func resourceOvhIpFirewallRuleCustomizeDiff(d *schema.ResourceDiff, v interface{}) error {
	protocol := d.Get("protocol")
	fragments := d.Get("fragments").(bool)
	tcpOption := d.Get("tcp_option")
	sourcePort := d.Get("source_port")
	destinationPort := d.Get("destination_port")

	if protocol == "tcp" {
		return nil
	}

	if fragments {
		return errors.New("fragments can only be set when using the tcp protocol.")
	}

	if tcpOption != "" {
		return errors.New("tcp_option can only be set when using the tcp protocol.")
	}

	if protocol == "udp" {
		return nil
	}

	if sourcePort != "" {
		return errors.New("source_port can only be set when using the tcp or udp protocols.")
	}

	if destinationPort != "" {
		return errors.New("destination_port can only be set when using the tcp or udp protocols.")
	}

	return nil
}

func resourceOvhIpFirewallRuleImportState(
	d *schema.ResourceData,
	meta interface{}) ([]*schema.ResourceData, error) {
	givenId := d.Id()
	splitId := strings.SplitN(givenId, "_", 3)
	if len(splitId) != 3 {
		return nil, fmt.Errorf("Import Id is not ip/ip_on_firewall_sequence formatted")
	}
	ip := splitId[0]
	ipOnFirewall := splitId[1]
	sequence := splitId[2]
	d.Set("ip", ip)
	d.Set("ip_on_firewall", ipOnFirewall)
	d.Set("sequence", sequence)
	results := make([]*schema.ResourceData, 1)
	results[0] = d
	return results, nil
}

func resourceOvhIpFirewallRuleCreate(d *schema.ResourceData, meta interface{}) error {
	provider := meta.(*Config)

	// Create the new firewall rule
	newIp := d.Get("ip").(string)
	newSequence := d.Get("sequence").(int)

	newIpOnFirewall, ok := d.GetOk("ip_on_firewall")
	if !ok || newIpOnFirewall == "" {
		ipAddr, ipNet, _ := net.ParseCIDR(newIp)
		prefixSize, _ := ipNet.Mask.Size()

		if ipAddr.To4() != nil && prefixSize != 32 {
			return fmt.Errorf("ip_address must be set if ip (%s) is not a /32", newIp)
		} else if ipAddr.To4() == nil && prefixSize != 128 {
			return fmt.Errorf("ip_address must be set if ip (%s) is not a /128", newIp)
		}

		newIpOnFirewall = ipAddr.String()
		d.Set("ip_on_firewall", newIpOnFirewall)
	}

	newFirewallRule := &OvhIpFirewallRuleCreateOpts{
		Action:          d.Get("action").(string),
		DestinationPort: d.Get("destination_port").(string),
		Fragments:       d.Get("fragments").(bool),
		Protocol:        d.Get("protocol").(string),
		Sequence:        newSequence,
		Source:          d.Get("source").(string),
		SourcePort:      d.Get("source_port").(string),
		TcpOption:       d.Get("tcp_option").(string),
	}

	log.Printf("[DEBUG] OVH IP Firewall create configuration: %s => %#v", newIpOnFirewall, newFirewallRule)

	resultFirewall := OvhIpFirewallRuleResponse{}

	err := provider.OVHClient.Post(
		fmt.Sprintf("/ip/%s/firewall/%s/rule", strings.Replace(newIp, "/", "%2F", 1), newIpOnFirewall),
		newFirewallRule,
		&resultFirewall,
	)

	if err != nil {
		return fmt.Errorf("Failed to create OVH IP Firewall Rule: %s", err)
	}

	log.Printf("[DEBUG] Waiting for Firewall rule %s=>%s=>%d", newIp, newIpOnFirewall, newSequence)

	stateConf := &resource.StateChangeConf{
		Pending:    []string{"creationPending", "removalPending"},
		Target:     []string{"ok"},
		Refresh:    waitForFirewallRuleState(provider.OVHClient, newIp, newIpOnFirewall.(string), newSequence),
		Timeout:    10 * time.Minute,
		Delay:      10 * time.Second,
		MinTimeout: 3 * time.Second,
	}

	_, err = stateConf.WaitForState()
	if err != nil {
		return fmt.Errorf("waiting for firewall rule (%s=>%s=>%d): %s", newIp, newIpOnFirewall, err)
	}

	d.SetId(fmt.Sprintf("%s_%s_%02d", newIp, newIpOnFirewall, resultFirewall.Sequence))

	return resourceOvhIpFirewallRuleRead(d, meta)
}

func resourceOvhIpFirewallRuleRead(d *schema.ResourceData, meta interface{}) error {
	provider := meta.(*Config)

	ip := d.Get("ip").(string)
	ipOnFirewall := d.Get("ip_on_firewall").(string)
	sequence := d.Get("sequence").(int)

	firewallRule := OvhIpFirewallRuleResponse{}
	err := provider.OVHClient.Get(
		fmt.Sprintf("/ip/%s/firewall/%s/rule/%d", strings.Replace(ip, "/", "%2F", 1), ipOnFirewall, sequence),
		&firewallRule,
	)

	if err != nil {
		d.SetId("")
		return nil
	}

	d.Set("action", firewallRule.Action)
	d.Set("destination_port", firewallRule.DestinationPort)
	d.Set("fragments", firewallRule.Fragments)
	d.Set("protocol", firewallRule.Protocol)
	d.Set("sequence", firewallRule.Sequence)
	d.Set("source", firewallRule.Source)
	d.Set("source_port", firewallRule.SourcePort)
	d.Set("tcp_option", firewallRule.TcpOption)
	d.Set("fragments", firewallRule.Fragments)
	d.Set("creation_date", firewallRule.CreationDate)
	d.Set("rule", firewallRule.Rule)
	d.Set("state", firewallRule.State)
	return nil
}

func resourceOvhIpFirewallRuleDelete(d *schema.ResourceData, meta interface{}) error {
	provider := meta.(*Config)

	ip := d.Get("ip").(string)
	ipOnFirewall := d.Get("ip_on_firewall").(string)
	sequence := d.Get("sequence").(int)

	log.Printf("[INFO] Deleting OVH IP Firewall Rule: %s->%s->%d", ip, ipOnFirewall, sequence)

	err := provider.OVHClient.Delete(
		fmt.Sprintf("/ip/%s/firewall/%s/rule/%d", strings.Replace(ip, "/", "%2F", 1), ipOnFirewall, sequence),
		nil,
	)
	if err != nil {
		return fmt.Errorf("Error deleting firewall rule: %s", err)
	}

	stateConf := &resource.StateChangeConf{
		Pending:    []string{"removalPending"},
		Target:     []string{"DELETED"},
		Refresh:    waitForFirewallRuleDelete(provider.OVHClient, ip, ipOnFirewall, sequence),
		Timeout:    10 * time.Minute,
		Delay:      10 * time.Second,
		MinTimeout: 3 * time.Second,
	}

	_, err = stateConf.WaitForState()
	if err != nil {
		return fmt.Errorf("deleting firewall rule %s -> %d: %s", ipOnFirewall, sequence, err)
	}

	d.SetId("")
	return nil
}

func resourceOvhIpFirewallRuleExists(ip, ipOnFirewall string, c *ovh.Client) error {
	firewall := OvhIpFirewallRuleResponse{}
	endpoint := fmt.Sprintf("/ip/%s/firewall/%s", strings.Replace(ip, "/", "%2F", 1), ipOnFirewall)

	err := c.Get(endpoint, &firewall)
	if err != nil {
		return fmt.Errorf("calling %s:\n\t %q", endpoint, err)
	}
	log.Printf("[DEBUG] Read IP Firewall: %s", firewall)

	return nil
}

// returns a resource.StateRefreshFunc that is used to watch firewall rule task
func waitForFirewallRuleState(c *ovh.Client, ip string, ipOnFirewall string, sequence int) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		r := &OvhIpFirewallRuleResponse{}
		endpoint := fmt.Sprintf("/ip/%s/firewall/%s/rule/%d", strings.Replace(ip, "/", "%2F", 1), ipOnFirewall, sequence)
		err := c.Get(endpoint, r)
		if err != nil {
			return r, "", err
		}

		log.Printf("[DEBUG] Pending Firewall Rule: %s", r)
		return r, r.State, nil
	}
}

// returns a resource.StateRefreshFunc that is used to watch firewall rule deletion task
func waitForFirewallRuleDelete(c *ovh.Client, ip string, ipOnFirewall string, sequence int) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		r := &OvhIpFirewallRuleResponse{}
		endpoint := fmt.Sprintf("/ip/%s/firewall/%s/rule/%d", strings.Replace(ip, "/", "%2F", 1), ipOnFirewall, sequence)
		err := c.Get(endpoint, r)
		if err != nil {
			if err.(*ovh.APIError).Code == 404 {
				log.Printf("[DEBUG] firewall rule %s -> %d deleted", ipOnFirewall, sequence)
				return r, "DELETED", nil
			} else {
				return r, "", err
			}
		}
		log.Printf("[DEBUG] Pending deletion of firewall rule %s -> %d: %s", ipOnFirewall, sequence, r)
		return r, r.State, nil
	}
}

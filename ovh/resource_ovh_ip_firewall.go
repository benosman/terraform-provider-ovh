package ovh

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"log"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"

	"github.com/ovh/go-ovh/ovh"
)

type OvhIpFirewallCreateOpts struct {
	IpOnFirewall string `json:"ipOnFirewall"`
}

type OvhIpFirewallUpdateOpts struct {
	Enabled bool `json:"enabled"`
}

type OvhIpFirewallResponse struct {
	IpOnFirewall string `json:"ipOnFirewall"`
	Enabled      bool   `json:"enabled"`
	State        string `json:"state"`
}

func resourceOvhIpFirewall() *schema.Resource {
	return &schema.Resource{
		Create: resourceOvhIpFirewallCreate,
		Read:   resourceOvhIpFirewallRead,
		Update: resourceOvhIpFirewallUpdate,
		Delete: resourceOvhIpFirewallDelete,
		Importer: &schema.ResourceImporter{
			State: resourceOvhIpFirewallImportState,
		},

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
			"enabled": {
				Type:        schema.TypeBool,
				Description: "Firewall Enabled",
				Required:    true,
			},
			"state": {
				Type:        schema.TypeString,
				Description: "Status of firewall: disableFirewallPending, enableFirewallPending, ok",
				Computed:    true,
			},
		},
	}
}

func resourceOvhIpFirewallImportState(
	d *schema.ResourceData,
	meta interface{}) ([]*schema.ResourceData, error) {
	givenId := d.Id()
	splitId := strings.SplitN(givenId, "_", 2)
	if len(splitId) != 2 {
		return nil, fmt.Errorf("Import Id is not ip/ip_on_firewall formatted")
	}
	ip := splitId[0]
	ipOnFirewall := splitId[1]
	d.Set("ip", ip)
	d.Set("ip_on_firewall", ipOnFirewall)
	results := make([]*schema.ResourceData, 1)
	results[0] = d
	return results, nil
}

func resourceOvhIpFirewallCreate(d *schema.ResourceData, meta interface{}) error {
	provider := meta.(*Config)

	// Create the new firewall
	newIp := d.Get("ip").(string)
	d.Set("ip", newIp)

	newEnabled := d.Get("enabled").(bool)
	d.Set("enabled", newEnabled)

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

	exists, existingFirewall, existingErr := resourceOvhIpFirewallExists(newIp, newIpOnFirewall.(string), provider.OVHClient)

	if existingErr != nil {
		return fmt.Errorf("Failed to create OVH IP Firewall: %s", existingErr)
	}

	if exists {
		if existingFirewall.Enabled == false && existingFirewall.State == "ok" {
			d.SetId(fmt.Sprintf("%s_%s", newIp, existingFirewall.IpOnFirewall))
			return resourceOvhIpFirewallUpdate(d, meta)
		} else {
			// TODO add parameter to control whether to adopt prexisting firewalls
			return fmt.Errorf("OVH IP Firewall %s -> %s already exists.", newIp, newIpOnFirewall, existingErr)
		}
	}

	newFirewall := &OvhIpFirewallCreateOpts{
		IpOnFirewall: d.Get("ip_on_firewall").(string),
	}

	log.Printf("[DEBUG] OVH IP Firewall create configuration: %s => %#v", newIp, newFirewall)

	resultFirewall := OvhIpFirewallResponse{}

	err := provider.OVHClient.Post(
		fmt.Sprintf("/ip/%s/firewall", strings.Replace(newIp, "/", "%2F", 1)),
		newFirewall,
		&resultFirewall,
	)

	if err != nil {
		return fmt.Errorf("Failed to create OVH IP Firewall: %s", err)
	}

	d.SetId(fmt.Sprintf("%s_%s", newIp, resultFirewall.IpOnFirewall))

	return resourceOvhIpFirewallUpdate(d, meta)
}

func resourceOvhIpFirewallRead(d *schema.ResourceData, meta interface{}) error {
	provider := meta.(*Config)

	firewall := OvhIpFirewallResponse{}
	err := provider.OVHClient.Get(
		fmt.Sprintf("/ip/%s/firewall/%s", strings.Replace(d.Get("ip").(string), "/", "%2F", 1), d.Get("ip_on_firewall").(string)),
		&firewall,
	)

	if err != nil {
		d.SetId("")
		return nil
	}

	d.Set("ip_on_firewall", firewall.IpOnFirewall)
	d.Set("enabled", firewall.Enabled)
	d.Set("state", firewall.State)
	return nil
}

func resourceOvhIpFirewallUpdate(d *schema.ResourceData, meta interface{}) error {
	provider := meta.(*Config)

	firewall := OvhIpFirewallUpdateOpts{}

	if attr, ok := d.GetOk("enabled"); ok {
		firewall.Enabled = attr.(bool)
	}

	ip := d.Get("ip").(string)
	ipOnFirewall := d.Get("ip_on_firewall").(string)

	log.Printf("[DEBUG] OVH IP Firewall update configuration for %s->%s: %#v", ip, ipOnFirewall, firewall)

	err := provider.OVHClient.Put(
		fmt.Sprintf("/ip/%s/firewall/%s", strings.Replace(ip, "/", "%2F", 1), ipOnFirewall),
		firewall,
		nil,
	)
	if err != nil {
		return fmt.Errorf("Failed to update OVH IP Firewall: %s", err)
	}

	log.Printf("[DEBUG] Waiting for Firewall Network %s=>%s", ip, ipOnFirewall)

	stateConf := &resource.StateChangeConf{
		Pending:    []string{"disableFirewallPending", "enableFirewallPending"},
		Target:     []string{"ok"},
		Refresh:    waitForFirewallState(provider.OVHClient, ip, ipOnFirewall),
		Timeout:    10 * time.Minute,
		Delay:      10 * time.Second,
		MinTimeout: 3 * time.Second,
	}

	_, err = stateConf.WaitForState()
	if err != nil {
		return fmt.Errorf("waiting for firewall network (%s=>%s): %s", ip, ipOnFirewall, err)
	}

	return resourceOvhIpFirewallRead(d, meta)
}

func resourceOvhIpFirewallDelete(d *schema.ResourceData, meta interface{}) error {
	provider := meta.(*Config)

	ip := d.Get("ip").(string)
	ipOnFirewall := d.Get("ip_on_firewall")

	log.Printf("[INFO] Deleting OVH IP Firewall: %s->%s", ip, ipOnFirewall)

	err := provider.OVHClient.Delete(
		fmt.Sprintf("/ip/%s/firewall/%s", strings.Replace(ip, "/", "%2F", 1), ipOnFirewall),
		nil,
	)

	if err != nil {
		return fmt.Errorf("Error deleting OVH IP Firewall: %s", err)
	}
	return nil
}

func resourceOvhIpFirewallExists(ip, ipOnFirewall string, c *ovh.Client) (bool, OvhIpFirewallResponse, error) {
	firewall := OvhIpFirewallResponse{}
	endpoint := fmt.Sprintf("/ip/%s/firewall/%s", strings.Replace(ip, "/", "%2F", 1), ipOnFirewall)

	err := c.Get(endpoint, &firewall)
	if err != nil {
		if err.(*ovh.APIError).Code == 404 {
			log.Printf("[DEBUG] firewall rule %s -> %s does not exist", ip, ipOnFirewall)
			return false, firewall, nil
		} else {
			return false, firewall, err
		}
	}
	log.Printf("[DEBUG] firewall rule %s -> %s already exists", ip, ipOnFirewall)
	return true, firewall, nil
}

// returns a resource.StateRefreshFunc that is used to watch firewall task
func waitForFirewallState(c *ovh.Client, ip string, ipOnFirewall string) resource.StateRefreshFunc {
	return func() (interface{}, string, error) {
		r := &OvhIpFirewallResponse{}
		endpoint := fmt.Sprintf("/ip/%s/firewall/%s", strings.Replace(ip, "/", "%2F", 1), ipOnFirewall)
		err := c.Get(endpoint, r)
		if err != nil {
			return r, "", err
		}

		log.Printf("[DEBUG] Pending Firewall: %s", r)
		return r, r.State, nil
	}
}

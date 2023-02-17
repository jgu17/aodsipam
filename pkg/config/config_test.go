package config

import (
	"fmt"
	"io/ioutil"
	"net"
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestAllocate(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "cmd")
}

var _ = Describe("Allocation operations", func() {
	It("can load a basic config", func() {

		conf := `{
      "cniVersion": "0.3.1",
      "name": "mynet",
      "type": "ipvlan",
      "master": "foo0",
        "ipam": {
          "type": "aodsipam",
          "log_file" : "/tmp/aodsipam.log",
          "log_level" : "debug",
          "kubernetes": {
            "kubeconfig": "/etc/cni/net.d/aodsipam.d/aodsipam.kubeconfig"
          },
          "range": "192.168.1.5-192.168.1.25/24",
          "gateway": "192.168.10.1"
        }
      }`

		ipamconfig, _, err := LoadIPAMConfig([]byte(conf), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(ipamconfig.LogLevel).To(Equal("debug"))
		Expect(ipamconfig.LogFile).To(Equal("/tmp/aodsipam.log"))
		Expect(ipamconfig.Gateway).To(Equal(net.ParseIP("192.168.10.1")))

	})

	It("can load a global flat-file config", func() {

		globalconf := `{
      "datastore": "kubernetes",
      "kubernetes": {
        "kubeconfig": "/etc/cni/net.d/aodsipam.d/aodsipam.kubeconfig"
      },
      "log_file": "/tmp/aodsipam.log",
      "log_level": "debug",
      "gateway": "192.168.5.5"
    }`

		err := ioutil.WriteFile("/tmp/aodsipam.conf", []byte(globalconf), 0755)
		Expect(err).NotTo(HaveOccurred())

		conf := `{
      "cniVersion": "0.3.1",
      "name": "mynet",
      "type": "ipvlan",
      "master": "foo0",
      "ipam": {
        "configuration_path": "/tmp/aodsipam.conf",
        "type": "aodsipam",
        "range": "192.168.2.230/24",
        "range_start": "192.168.2.223",
        "gateway": "192.168.10.1",
        "leader_lease_duration": 3000,
        "leader_renew_deadline": 2000,
        "leader_retry_period": 1000
      }
      }`

		ipamconfig, _, err := LoadIPAMConfig([]byte(conf), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(ipamconfig.LogLevel).To(Equal("debug"))
		Expect(ipamconfig.LogFile).To(Equal("/tmp/aodsipam.log"))
		// Gateway should remain unchanged from conf due to preference for primary config
		Expect(ipamconfig.Gateway).To(Equal(net.ParseIP("192.168.10.1")))
		Expect(ipamconfig.Kubernetes.KubeConfigPath).To(Equal("/etc/cni/net.d/aodsipam.d/aodsipam.kubeconfig"))

	})

	It("overlapping range can be set", func() {
		var globalConf string = `{
			"datastore": "kubernetes",
			"kubernetes": {
				"kubeconfig": "/etc/cni/net.d/aodsipam.d/aodsipam.kubeconfig"
			},
			"log_file": "/tmp/aodsipam.log",
			"log_level": "debug",
			"gateway": "192.168.5.5",
			"enable_overlapping_ranges": false
		}`
		Expect(ioutil.WriteFile("/tmp/aodsipam.conf", []byte(globalConf), 0755)).To(Succeed())

		_, _, err := LoadIPAMConfig([]byte(generateIPAMConfWithOverlappingRanges()), "")
		Expect(err).NotTo(HaveOccurred())

	})

	It("overlapping range can be disabled", func() {
		var globalConf string = `{
			"datastore": "kubernetes",
			"kubernetes": {
				"kubeconfig": "/etc/cni/net.d/aodsipam.d/aodsipam.kubeconfig"
			},
			"log_file": "/tmp/aodsipam.log",
			"log_level": "debug",
			"gateway": "192.168.5.5",
			"enable_overlapping_ranges": true
		}`
		Expect(ioutil.WriteFile("/tmp/aodsipam.conf", []byte(globalConf), 0755)).To(Succeed())

		_, _, err := LoadIPAMConfig([]byte(generateIPAMConfWithoutOverlappingRanges()), "")
		Expect(err).NotTo(HaveOccurred())

	})

	It("can load a config list", func() {
		conf := `{
        "cniVersion": "0.3.0",
        "disableCheck": true,
        "plugins": [
            {
                "type": "macvlan",
                "master": "eth0",
                "mode": "bridge",
                "ipam": {
                    "type": "aodsipam",
                    "leader_lease_duration": 1500,
                    "leader_renew_deadline": 1000,
                    "leader_retry_period": 500,
                    "range": "192.168.1.5-192.168.1.25/24",
                    "gateway": "192.168.10.1",
                    "log_level": "debug",
                    "log_file": "/tmp/aodsipam.log",
					"kubernetes": {
					  "kubeconfig": "/etc/cni/net.d/aodsipam.d/aodsipam.kubeconfig"
					}
                }
            }
        ]
    }`

		ipamconfig, err := LoadIPAMConfiguration([]byte(conf), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(ipamconfig.LogLevel).To(Equal("debug"))
		Expect(ipamconfig.LogFile).To(Equal("/tmp/aodsipam.log"))
		Expect(ipamconfig.Gateway).To(Equal(net.ParseIP("192.168.10.1")))
	})

	It("throws an error when passed a non-aodsipam IPAM config", func() {
		const wrongPluginType = "static"
		conf := fmt.Sprintf(`{
      "cniVersion": "0.3.1",
      "name": "mynet",
      "type": "ipvlan",
      "master": "foo0",
      "ipam": {
        "type": "%s"
      }
      }`, wrongPluginType)

		_, _, err := LoadIPAMConfig([]byte(conf), "")
		Expect(err).To(MatchError(&InvalidPluginError{ipamType: wrongPluginType}))
	})

	It("allows for leading zeroes in the range in start/end range format", func() {
		conf := `{
      "cniVersion": "0.3.1",
      "name": "mynet",
      "type": "ipvlan",
      "master": "foo0",
        "ipam": {
          "type": "aodsipam",
          "log_file" : "/tmp/aodsipam.log",
          "log_level" : "debug",
          "kubernetes": {
            "kubeconfig": "/etc/cni/net.d/aodsipam.d/aodsipam.kubeconfig"
          },
          "range": "00192.00168.1.5-000000192.168.1.25/24",
          "gateway": "192.168.10.1"
        }
      }`

		_, _, err := LoadIPAMConfig([]byte(conf), "")
		Expect(err).NotTo(HaveOccurred())
	})

	It("allows for leading zeroes in the range", func() {
		conf := `{
      "cniVersion": "0.3.1",
      "name": "mynet",
      "type": "ipvlan",
      "master": "foo0",
        "ipam": {
          "type": "aodsipam",
          "log_file" : "/tmp/aodsipam.log",
          "log_level" : "debug",
          "kubernetes": {
            "kubeconfig": "/etc/cni/net.d/aodsipam.d/aodsipam.kubeconfig"
          },
          "range": "00192.00168.1.0/24",
          "gateway": "192.168.10.1"
        }
      }`

		_, _, err := LoadIPAMConfig([]byte(conf), "")
		Expect(err).NotTo(HaveOccurred())
	})

	It("allows for leading zeroes in the range when the start range is provided", func() {
		conf := `{
      "cniVersion": "0.3.1",
      "name": "mynet",
      "type": "ipvlan",
      "master": "foo0",
        "ipam": {
          "type": "aodsipam",
          "log_file" : "/tmp/aodsipam.log",
          "log_level" : "debug",
          "kubernetes": {
            "kubeconfig": "/etc/cni/net.d/aodsipam.d/aodsipam.kubeconfig"
          },
          "range": "00192.00168.1.0/24",
          "range_start": "00192.00168.1.44",
          "gateway": "192.168.10.1"
        }
      }`

		_, _, err := LoadIPAMConfig([]byte(conf), "")
		Expect(err).NotTo(HaveOccurred())
	})

	It("allows for leading zeroes in the range when the start and end ranges are provided", func() {
		conf := `{
      "cniVersion": "0.3.1",
      "name": "mynet",
      "type": "ipvlan",
      "master": "foo0",
        "ipam": {
          "type": "aodsipam",
          "log_file" : "/tmp/aodsipam.log",
          "log_level" : "debug",
          "kubernetes": {
            "kubeconfig": "/etc/cni/net.d/aodsipam.d/aodsipam.kubeconfig"
          },
          "range": "00192.00168.1.0/24",
          "range_start": "00192.00168.1.44",
          "range_end": "00192.00168.01.209",
          "gateway": "192.168.10.1"
        }
      }`

		_, _, err := LoadIPAMConfig([]byte(conf), "")
		Expect(err).NotTo(HaveOccurred())

	})

	It("can unmarshall the cronjob expression", func() {
		conf := `{
      "cniVersion": "0.3.1",
      "name": "mynet",
      "type": "ipvlan",
      "master": "foo0",
        "ipam": {
          "type": "aodsipam",
          "log_file" : "/tmp/aodsipam.log",
          "log_level" : "debug",
          "kubernetes": {
            "kubeconfig": "/etc/cni/net.d/aodsipam.d/aodsipam.kubeconfig"
          },
          "range": "00192.00168.1.0/24",
          "range_start": "00192.00168.1.44",
          "range_end": "00192.00168.01.209",
          "gateway": "192.168.10.1",
          "reconciler_cron_expression": "30 4 * * *"
        }
      }`

		ipamConfig, _, err := LoadIPAMConfig([]byte(conf), "")
		Expect(err).NotTo(HaveOccurred())
		Expect(ipamConfig.ReconcilerCronExpression).To(Equal("30 4 * * *"))
	})

	It("errors when an invalid range specified", func() {
		invalidConf := `{
			"cniVersion": "0.3.1",
            "name": "mynet",
			"type": "ipvlan",
			"master": "foo0",
			"ipam": {
				"type": "aodsipam",
				"log_file" : "/tmp/aodsipam.log",
				"log_level" : "debug",
				"range": "192.168.1.5-192.168.2.25/28",
				"gateway": "192.168.10.1"
			}
		}`
		_, _, err := LoadIPAMConfig([]byte(invalidConf), "")
		Expect(err).To(MatchError("invalid range start for CIDR 192.168.2.16/28: 192.168.1.5"))
	})

	It("errors when an invalid IPAM struct is specified", func() {
		invalidConf := `{
			"cniVersion": "0.3.1",
            "name": "mynet",
			"type": "ipvlan",
			"master": "foo0",
			"ipam": {
				asdf
			}
		}`
		_, _, err := LoadIPAMConfig([]byte(invalidConf), "")
		Expect(err).To(
			MatchError(
				HavePrefix(
					"LoadIPAMConfig - JSON Parsing Error: invalid character 'a' looking for beginning of object key string")))
	})
})

func generateIPAMConfWithOverlappingRanges() string {
	return `{
		"cniVersion": "0.3.1",
		"name": "mynet",
		"type": "ipvlan",
		"master": "foo0",
		"ipam": {
			"range": "192.168.2.230/24",
			"configuration_path": "/tmp/aodsipam.conf",
			"type": "aodsipam",
			"enable_overlapping_ranges": true
		}
	}`
}

func generateIPAMConfWithoutOverlappingRanges() string {
	return `{
		"cniVersion": "0.3.1",
		"name": "mynet",
		"type": "ipvlan",
		"master": "foo0",
		"ipam": {
			"range": "192.168.2.230/24",
			"configuration_path": "/tmp/aodsipam.conf",
			"type": "aodsipam",
			"enable_overlapping_ranges": false
		}
	}`
}

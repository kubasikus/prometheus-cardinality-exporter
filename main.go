package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github/thought-machine/prometheus-cardinality-exporter/cardinality"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cenkalti/backoff/v4"
	"github.com/jessevdk/go-flags"
	logging "github.com/sirupsen/logrus"
)

var log = logging.WithFields(logging.Fields{})

var opts struct {
	Selector              string   `long:"selector" short:"s" default:"app=prometheus" help:"Selector for Service Discovery."`
	Namespaces            []string `long:"namespaces" short:"n"  help:"Namespaces for Service Discovery."`
	PrometheusInstances   []string `long:"proms" short:"i" help:"Prometheus instance links. Mutually exclusive to the service discover flag."`
	PromAPIAuthValuesFile string   `long:"auth" short:"a" help:"Location of YAML file where Prometheus instance authorisation credentials can be found. For instances that don't appear in the file, it is assumed that no authorisation is required to access them."`
	ServiceDiscovery      bool     `long:"service_discovery" short:"d" help:"Service discovery flag, use service discovery to find new instances of Prometheus within a cluster. Mutually exclusive to the prometheus instance link flag."`
	Port                  int      `long:"port" short:"p" default:"9090" help:"Port on which to serve."`
	Frequency             float32  `long:"freq" short:"f" default:"6" help:"Frequency in hours with which to query the Prometheus API."`
	ServiceRegex          string   `long:"regex" short:"r" default:"prometheus-[a-zA-Z0-9_-]+" help:"If any found services don't match the regex, they are ignored."`
	LogLevel              string   `long:"log.level" short:"l" default:"info" help:"Level for logging. Options (in order of verbosity): [debug, info, warn, error, fatal]."`
	StatsLimit            int      `long:"stats-limit" short:"L" default:"10" help:"Limit the number of items fetched from the TSDB statistics."`
}

// InstanceAuthConfig holds per-instance authentication and connection settings.
// Supports both the legacy single-header format and the extended format with
// TLS CA, ServiceAccount auth, custom port, and multiple headers.
type InstanceAuthConfig struct {
	Headers       []string `yaml:"headers"`
	CA            string   `yaml:"ca"`
	SAAuth        bool     `yaml:"sa_auth"`
	Port          string   `yaml:"port"`
	TLSServerName string   `yaml:"tls_server_name"`
}

// buildHTTPClientForInstance returns an *http.Client appropriate for the given
// instance config. If no CA is configured, it returns a plain default client.
// defaultServerName is used for TLS ServerName verification when the config
// does not specify an explicit tls_server_name override.
func buildHTTPClientForInstance(config *InstanceAuthConfig, defaultServerName string) *http.Client {
	if config == nil || config.CA == "" {
		return &http.Client{}
	}

	caCert, err := os.ReadFile(config.CA)
	if err != nil {
		log.Errorf("Failed to read CA file %s: %v. Falling back to default HTTP client.", config.CA, err)
		return &http.Client{}
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Errorf("Failed to parse CA certificate from %s. Falling back to default HTTP client.", config.CA)
		return &http.Client{}
	}

	serverName := config.TLSServerName
	if serverName == "" {
		serverName = defaultServerName
	}

	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}
	if serverName != "" {
		tlsConfig.ServerName = serverName
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

const saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// readSAToken reads the pod's default ServiceAccount token from the well-known
// path and returns it as a formatted "Bearer <token>" string. Returns an empty
// string if the file cannot be read.
func readSAToken() string {
	tokenBytes, err := os.ReadFile(saTokenPath)
	if err != nil {
		log.Errorf("Failed to read ServiceAccount token from %s: %v", saTokenPath, err)
		return ""
	}
	return "Bearer " + strings.TrimSpace(string(tokenBytes))
}

// resolveHeaders returns the effective set of HTTP headers for an instance config.
// It copies config.Headers and, when sa_auth is enabled, prepends a fresh
// ServiceAccount bearer token as an Authorization header. This is non-mutating
// and safe to call every scrape cycle.
func resolveHeaders(config *InstanceAuthConfig) []string {
	if config == nil {
		return nil
	}
	headers := make([]string, len(config.Headers))
	copy(headers, config.Headers)

	if config.SAAuth {
		token := readSAToken()
		if token != "" {
			headers = append([]string{"Authorization: " + token}, headers...)
		}
	}
	return headers
}

// lookupAuthConfig performs a cascading lookup for the auth config matching
// the given keys, returning the first match or nil.
func lookupAuthConfig(authConfigs map[string]*InstanceAuthConfig, keys ...string) *InstanceAuthConfig {
	for _, key := range keys {
		if config, ok := authConfigs[key]; ok {
			return config
		}
	}
	return nil
}

// loadAuthConfig reads the auth YAML file and returns a map of instance identifiers
// to their auth/connection configuration. It supports two formats:
//
// Legacy (string value):
//
//	"identifier": "Bearer eyJ..."
//
// Extended (map value):
//
//	"identifier":
//	  headers: ["Authorization: Bearer eyJ..."]
//	  ca: "/path/to/ca.crt"
//	  sa_auth: true
//	  port: "9091"
func loadAuthConfig(path string) map[string]*InstanceAuthConfig {
	if path == "" {
		return nil
	}

	filename, err := filepath.Abs(path)
	if err != nil {
		log.Errorf("Failed to obtain the filepath of the Prometheus API authorisation values file provided: %v.", err.Error())
		return nil
	}

	fileContents, err := os.ReadFile(filename)
	if err != nil {
		log.Errorf("Failed to read Prometheus API authorisation values file provided: %v.", err.Error())
		return nil
	}

	var raw map[string]any
	if err := yaml.Unmarshal(fileContents, &raw); err != nil {
		log.Errorf("Failed to parse Prometheus API authorisation values file: %v. Check the format of your file!", err.Error())
		return nil
	}

	if len(raw) == 0 {
		log.Errorf("Skipping the authorisation component to continue collecting metrics from Prometheus instances that don't require authorisation. This will result in no metrics from secured Prometheus instances.")
		return nil
	}

	configs := make(map[string]*InstanceAuthConfig, len(raw))
	for key, value := range raw {
		switch v := value.(type) {
		case string:
			// Legacy format: "identifier": "Authorization header value"
			configs[key] = &InstanceAuthConfig{
				Headers: []string{"Authorization: " + v},
			}
		case map[string]interface{}:
			// Extended format: re-marshal and unmarshal into InstanceAuthConfig
			bytes, err := yaml.Marshal(v)
			if err != nil {
				log.Errorf("Failed to re-marshal config for key %q: %v", key, err)
				continue
			}
			var cfg InstanceAuthConfig
			if err := yaml.Unmarshal(bytes, &cfg); err != nil {
				log.Errorf("Failed to parse extended config for key %q: %v", key, err)
				continue
			}
			configs[key] = &cfg
		default:
			log.Errorf("Unexpected value type for key %q in auth config file, skipping.", key)
		}
	}

	return configs
}

// loadManualInstances parses the manually provided Prometheus URLs (--proms) and populates
// the cardinalityInfoByInstance map with their instance name, namespace, and auth credentials.
// In this case the name of the sharded instance is the same as the name of the prometheus instance
// because it is not possible to distinguish between them based on addresses given as arguments.
func loadManualInstances(cardinalityInfoByInstance map[string]*cardinality.PrometheusCardinalityInstance, authConfigs map[string]*InstanceAuthConfig) {
	// Captures the instance name and namespace from URLs like http(s)://<instance>.<namespace>...
	regexC := regexp.MustCompile(`https?://([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)`)

	for _, prometheusInstanceAddress := range opts.PrometheusInstances {

		matches := regexC.FindStringSubmatch(prometheusInstanceAddress)
		if matches == nil {
			log.Fatalf("%v is not a valid prometheus instance address.", prometheusInstanceAddress)
		}
		instanceName := matches[1]
		namespace := matches[2]

		instanceID := namespace + "_" + instanceName

		// Add the prometheus instance to the data structure
		cardinalityInfoByInstance[instanceID] = &cardinality.PrometheusCardinalityInstance{
			Namespace:           namespace,
			InstanceName:        instanceName,
			ShardedInstanceName: instanceName,
			InstanceAddress:     prometheusInstanceAddress,
			TrackedLabels: cardinality.TrackedLabelNames{
				SeriesCountByMetricNameLabels:     make([]string, 0, opts.StatsLimit),
				LabelValueCountByLabelNameLabels:  make([]string, 0, opts.StatsLimit),
				MemoryInBytesByLabelNameLabels:    make([]string, 0, opts.StatsLimit),
				SeriesCountByLabelValuePairLabels: make([]string, 0, opts.StatsLimit),
			},
		}
	}
}

// discoverInstances uses Kubernetes service discovery to find Prometheus endpoints
// matching the configured selector and regex, and populates the cardinalityInfoByInstance map.
// Port and scheme are resolved from the auth config when available.
func discoverInstances(cardinalityInfoByInstance map[string]*cardinality.PrometheusCardinalityInstance, authConfigs map[string]*InstanceAuthConfig) {
	// Obtains the cluster config of the cluster we are currently in
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Error obtaining the current cluster config: %v", err.Error())
	}

	// Creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Error creating the clientset from the cluster config: %v", err.Error())
	}

	// If namespaces are specified as arguments use them, if not use service discovery
	var namespaceList []string
	if len(opts.Namespaces) == 0 {
		// Accesses the API to list all namespaces in the cluster
		namespaces, _ := clientset.CoreV1().Namespaces().List(context.TODO(), v1.ListOptions{})
		for _, namespaceObj := range namespaces.Items {
			namespaceList = append(namespaceList, namespaceObj.ObjectMeta.GetName())
		}
	} else {
		namespaceList = opts.Namespaces
	}

	for _, namespace := range namespaceList {

		// Accesses the API to list all endpoints and services which match the label selector in the given namespace
		endpointsList, _ := clientset.CoreV1().Endpoints(namespace).List(context.TODO(), v1.ListOptions{LabelSelector: opts.Selector})

		if err != nil {
			log.Fatalf("Error obtaining endpoints matching selector (%v) in namespace (%v): %v", namespace, opts.Selector, err.Error())
		}

		// Iterate over all of the endpoints and add them to the data structure
		for _, endpoints := range endpointsList.Items { // This loop represents a service

			prometheusInstanceName := endpoints.ObjectMeta.GetName()
			//If the instance name doesn't start with the chosen prefix, it is ignored
			if matched, _ := regexp.MatchString(opts.ServiceRegex, prometheusInstanceName); !matched {
				continue
			}

			for _, endpointSubset := range endpoints.Subsets { // This loop represents groups of endpoints within a service

				for _, address := range endpointSubset.Addresses { // This loop represents each individual endpoint
					shardedInstanceName := address.TargetRef.Name // Name of sharded instance e.g. prometheus-kubernetes-0
					instanceID := namespace + "_" + prometheusInstanceName + "_" + shardedInstanceName

					// Cascading auth config lookup: sharded instance -> instance -> namespace
					authCfg := lookupAuthConfig(authConfigs,
						instanceID,
						namespace+"_"+prometheusInstanceName,
						namespace,
					)

					// Resolve port and scheme from auth config
					port := "9090"
					scheme := "http"
					if authCfg != nil {
						if authCfg.Port != "" {
							port = authCfg.Port
						}
						if authCfg.CA != "" {
							scheme = "https"
						}
					}
					instanceAddress := fmt.Sprintf("%s://%s:%s", scheme, address.IP, port)

					if _, ok := cardinalityInfoByInstance[instanceID]; !ok {
						// Add a newly found endpoint to the data structure
						cardinalityInfoByInstance[instanceID] = &cardinality.PrometheusCardinalityInstance{
							Namespace:           namespace,
							InstanceName:        prometheusInstanceName,
							ShardedInstanceName: shardedInstanceName,
							InstanceAddress:     instanceAddress,
							TrackedLabels: cardinality.TrackedLabelNames{
								SeriesCountByMetricNameLabels:     make([]string, 0, opts.StatsLimit),
								LabelValueCountByLabelNameLabels:  make([]string, 0, opts.StatsLimit),
								MemoryInBytesByLabelNameLabels:    make([]string, 0, opts.StatsLimit),
								SeriesCountByLabelValuePairLabels: make([]string, 0, opts.StatsLimit),
							},
						}
					} else {
						// If the endpoint is already known, update its address
						cardinalityInfoByInstance[instanceID].InstanceAddress = instanceAddress
					}
				}
			}
		}
	}
}

func collectMetrics() {

	// Number of times to retry before fetching the data before giving up.
	// If the number of retries is exhausted, it will wait until the next time it has to query the Prometheus API.
	var numRetries uint64 = 3
	sleepTime, err := time.ParseDuration(fmt.Sprintf("%0.4fh", opts.Frequency))
	if err != nil {
		log.Errorf("Cannot parse frequency variable %v: %v", opts.Frequency, err)
	}

	// Map of prometheus instance identifiers to their auth/connection configuration
	authConfigs := loadAuthConfig(opts.PromAPIAuthValuesFile)

	// This is a data structure that allows for the storage of the names prometheus instances and their sharded instances
	// Sharded instances are specified because a service may have several endpoints
	// Ignoring this would result in kubernetes selecting only one endpoint per API call, which could lead to inconsistent metric reporting
	// Each sharded instance also stores it's address (which can change), the latest cardinality info, and the current tracked labels
	cardinalityInfoByInstance := make(map[string]*cardinality.PrometheusCardinalityInstance)

	if !opts.ServiceDiscovery { // Prometheus instances defined by arguments
		loadManualInstances(cardinalityInfoByInstance, authConfigs)
	}

	for {
		if opts.ServiceDiscovery {
			discoverInstances(cardinalityInfoByInstance, authConfigs)
		}

		// Iterates over all prometheus instances and runs cardinality exporter logic
		for instanceID, instance := range cardinalityInfoByInstance {

			// Cascading auth config lookup: sharded instance -> instance -> namespace -> full URL
			authCfg := lookupAuthConfig(authConfigs,
				instanceID,
				instance.Namespace+"_"+instance.InstanceName,
				instance.Namespace,
				instance.InstanceAddress,
			)

			// Resolve headers each cycle so SA tokens are always fresh
			instance.Headers = resolveHeaders(authCfg)
			serviceDNS := instance.InstanceName + "." + instance.Namespace + ".svc"
			prometheusClient := buildHTTPClientForInstance(authCfg, serviceDNS)

			log.Infof("Fetching current Prometheus status, from Prometheus instance: %v. Sharded instance: %v. Namespace: %v.", instance.InstanceName, instance.ShardedInstanceName, instance.Namespace)

			if len(instance.Headers) > 0 {
				log.Info("Including custom headers.")
			}

			// Fetch the data from Prometheus
			err := backoff.Retry(func() error {
				return cardinalityInfoByInstance[instanceID].FetchTSDBStatus(prometheusClient, opts.StatsLimit)
			}, backoff.WithMaxRetries(backoff.NewExponentialBackOff(), numRetries))
			if err != nil {
				log.WithError(err).Warningf("Error fetching Prometheus status: %v", err)
				delete(cardinalityInfoByInstance, instanceID)
				continue
			}

			// Expose data on /metrics
			err = backoff.Retry(func() error {
				return cardinalityInfoByInstance[instanceID].ExposeTSDBStatus(&cardinality.SeriesCountByMetricNameGauge, &cardinality.LabelValueCountByLabelNameGauge, &cardinality.MemoryInBytesByLabelNameGauge, &cardinality.SeriesCountByLabelValuePairGauge)
			}, backoff.WithMaxRetries(backoff.NewExponentialBackOff(), numRetries))
			if err != nil {
				log.WithError(err).Warningf("Error exposing Prometheus metrics: %v", err)
			}
		}

		// Sleep until next metric update
		log.Debugf("Sleeping for %0.4f hours.", opts.Frequency)
		time.Sleep(sleepTime)
	}
}

func main() {
	_, err := flags.Parse(&opts)

	// Exit gracefully if help flag used
	if err != nil && flags.WroteHelp(err) {
		os.Exit(0)
	} else if err != nil {
		log.Fatalf("%+v", err)
	}

	if len(opts.PrometheusInstances) > 0 && opts.ServiceDiscovery {
		log.Fatal("Cannot parse Prometheus Instances (--proms) AND use Service Discovery (--service_discovery), these options are mutually exclusive.")
	} else if len(opts.PrometheusInstances) > 0 {
		log.Info("Obtaining metrics from prometheus instances specified as arguments.")
	} else if opts.ServiceDiscovery {
		log.Info("Obtaining metrics from services found with service discovery.")
	} else {
		log.Fatal("Service Discovery has not been selected (--service_discovery) and no Prometheus Instances (--proms) have been passed, therefore there are no Prometheus Instances to connect to.")
	}

	logLevel, err := logging.ParseLevel(opts.LogLevel)
	if err != nil {
		log.Warnf("Invalid log level \"%s\", setting log level to \"info\".", opts.LogLevel)
		logLevel = logging.InfoLevel
	}
	logging.SetLevel(logLevel)

	log.Infof("Serving on port: %d", opts.Port)
	log.Infof("Serving Prometheus metrics on /metrics")
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	})

	log.Infof("Starting Prometheus cardinality metric collection.")
	go collectMetrics()

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", opts.Port), nil))
}
